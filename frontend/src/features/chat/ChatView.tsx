import { ChangeEvent, FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LoadingState } from "../../components/LoadingState";
import { useEventStream } from "../../hooks/useEventStream";
import { useAuthStore, useChatStore } from "../../store";
import { api } from "../../services/api";
import type { ChatTarget, RealtimeEvent, User } from "../../types";

function decodeUserIdFromToken(token?: string): number | null {
  if (!token) return null;
  try {
    const payloadPart = token.split(".")[1];
    if (!payloadPart) return null;
    const payload = JSON.parse(atob(payloadPart));
    const userId = Number(payload.userId);
    return Number.isFinite(userId) ? userId : null;
  } catch {
    return null;
  }
}

export function ChatView() {
  const { user, logout, updateProfile } = useAuthStore();
  const {
    users,
    groups,
    onlineUserIds,
    blockedUserIds,
    selected,
    messages,
    loading,
    error,
    bootstrap,
    refreshOnline,
    setOnlineStatus,
    createGroup,
    addMemberToGroup,
    blockUser,
    unblockUser,
    selectChat,
    sendMessage,
    sendMedia,
    sendLocation,
    sendTyping,
    appendIncoming
  } = useChatStore();

  const [draft, setDraft] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupMembers, setGroupMembers] = useState<number[]>([]);
  const [newMemberId, setNewMemberId] = useState<number | "">("");
  const [typingFromUserId, setTypingFromUserId] = useState<number | null>(null);
  const [recording, setRecording] = useState(false);
  const [showAttachMenu, setShowAttachMenu] = useState(false);
  const [showEmojiMenu, setShowEmojiMenu] = useState(false);
  const [showProfileModal, setShowProfileModal] = useState(false);
  const [activeProfile, setActiveProfile] = useState<User | null>(null);
  const [profileUsername, setProfileUsername] = useState("");
  const [profileFullName, setProfileFullName] = useState("");
  const [profileBio, setProfileBio] = useState("");
  const [profileAvatarUrl, setProfileAvatarUrl] = useState("");
  const typingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mediaInputRef = useRef<HTMLInputElement | null>(null);
  const documentInputRef = useRef<HTMLInputElement | null>(null);
  const avatarInputRef = useRef<HTMLInputElement | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const mediaChunksRef = useRef<Blob[]>([]);

  useEffect(() => {
    if (!user) return;
    const resolvedUserId = typeof user.id === "number" ? user.id : decodeUserIdFromToken(user.token);
    if (!resolvedUserId) return;
    void bootstrap(resolvedUserId);
  }, [user, bootstrap]);

  useEffect(() => {
    if (!user) return;
    void refreshOnline();
    const timer = setInterval(() => {
      void refreshOnline();
    }, 15000);
    return () => clearInterval(timer);
  }, [user, refreshOnline]);

  const handleRealtimeEvent = useCallback((event: RealtimeEvent) => {
    if (event.type === "message") {
      appendIncoming(event);
      return;
    }

    if (event.type === "typing") {
      setTypingFromUserId(event.from);
      if (typingTimerRef.current) {
        clearTimeout(typingTimerRef.current);
      }
      typingTimerRef.current = setTimeout(() => {
        setTypingFromUserId(null);
      }, 2500);
      return;
    }

    if (event.type === "user_online") {
      setOnlineStatus(event.userId, true);
      return;
    }

    if (event.type === "user_offline") {
      setOnlineStatus(event.userId, false);
    }
  }, [appendIncoming, setOnlineStatus]);

  useEventStream({ userId: user?.id, onEvent: handleRealtimeEvent });

  const contactItems = useMemo(
    () =>
      users.map((entry) => ({
        kind: "user" as const,
        id: entry.id,
        label: entry.fullName || entry.username,
        online: onlineUserIds.includes(entry.id)
      })),
    [users, onlineUserIds]
  );

  const groupItems = useMemo(
    () =>
      groups.map((group) => ({
        kind: "group" as const,
        id: group.id,
        label: `# ${group.name}`
      })),
    [groups]
  );

  if (!user) return null;
  const currentUserId = typeof user.id === "number" ? user.id : decodeUserIdFromToken(user.token);
  if (!currentUserId) return null;

  const onSelect = (target: ChatTarget) => {
    void selectChat(target, currentUserId);
  };

  const onSend = (event: FormEvent) => {
    event.preventDefault();
    void sendMessage(draft, currentUserId);
    setDraft("");
  };

  const selectedGroup =
    selected?.kind === "group" ? groups.find((group) => group.id === selected.id) ?? null : null;

  const selectedUserBlocked = selected?.kind === "user" ? blockedUserIds.includes(selected.id) : false;

  const submitGroup = (event: FormEvent) => {
    event.preventDefault();
    void createGroup(groupName, groupMembers, currentUserId);
    setGroupName("");
    setGroupMembers([]);
  };

  const addMember = () => {
    if (!selectedGroup || !newMemberId) return;
    void addMemberToGroup(selectedGroup.id, Number(newMemberId), currentUserId);
    setNewMemberId("");
  };

  const typingVisible =
    selected?.kind === "user" && typingFromUserId === selected.id && !selectedUserBlocked;

  const inferMediaType = (file: File) => {
    if (file.type.startsWith("image/")) return "image";
    if (file.type.startsWith("video/")) return "video";
    if (file.type.startsWith("audio/")) return "audio";
    return "file";
  };

  const handleFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    if (!user || !event.target.files?.length) return;
    const file = event.target.files[0];
    try {
      const uploaded = await api.upload(file);
      await sendMedia(uploaded.url, inferMediaType(file), currentUserId);
    } finally {
      event.target.value = "";
      setShowAttachMenu(false);
    }
  };

  const startRecording = async () => {
    if (recording || !user) return;
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const recorder = new MediaRecorder(stream);
    mediaRecorderRef.current = recorder;
    mediaChunksRef.current = [];

    recorder.ondataavailable = (e) => {
      if (e.data.size > 0) {
        mediaChunksRef.current.push(e.data);
      }
    };

    recorder.onstop = async () => {
      const blob = new Blob(mediaChunksRef.current, { type: "audio/webm" });
      const file = new File([blob], `voice-${Date.now()}.webm`, { type: "audio/webm" });
      const uploaded = await api.upload(file);
      await sendMedia(uploaded.url, "audio", currentUserId);
      stream.getTracks().forEach((track) => track.stop());
      setRecording(false);
    };

    recorder.start();
    setRecording(true);
  };

  const stopRecording = () => {
    mediaRecorderRef.current?.stop();
  };

  const shareLocation = () => {
    if (!user || !navigator.geolocation) return;
    navigator.geolocation.getCurrentPosition((position) => {
      void sendLocation(position.coords.latitude, position.coords.longitude, currentUserId);
    });
    setShowAttachMenu(false);
  };

  const emojiItems = ["😀", "😂", "😍", "🙏", "👍", "🔥", "❤️", "🎉", "😢", "🤝"];

  const openProfile = async (targetUserId?: number) => {
    const resolvedUserId = typeof targetUserId === "number" ? targetUserId : currentUserId;
    if (!resolvedUserId) return;
    const fallbackUser = [user, ...users].find((entry) => entry && entry.id === resolvedUserId) || null;
    const profile = await api.profile(resolvedUserId).catch(() => fallbackUser);
    if (!profile) return;
    setActiveProfile(profile);
    setProfileUsername(profile.username || "");
    setProfileFullName(profile.fullName || "");
    setProfileBio(profile.bio || "");
    setProfileAvatarUrl(profile.avatarUrl || "");
    setShowProfileModal(true);
  };

  const onProfileSave = async (event: FormEvent) => {
    event.preventDefault();
    if (!activeProfile || activeProfile.id !== currentUserId) {
      setShowProfileModal(false);
      return;
    }
    const ok = await updateProfile({
      username: profileUsername.trim(),
      fullName: profileFullName.trim(),
      bio: profileBio.trim(),
      avatarUrl: profileAvatarUrl.trim()
    });
    if (ok) {
      setActiveProfile({
        ...activeProfile,
        username: profileUsername.trim(),
        fullName: profileFullName.trim(),
        bio: profileBio.trim(),
        avatarUrl: profileAvatarUrl.trim()
      });
      void bootstrap(currentUserId);
      setShowProfileModal(false);
    }
  };

  const onAvatarChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const uploaded = await api.upload(file);
    setProfileAvatarUrl(uploaded.url);
    event.target.value = "";
  };

  const isOwnProfile = !!(activeProfile && activeProfile.id === currentUserId);

  return (
    <div className="chat-layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <button className="profile-chip" type="button" onClick={() => void openProfile(currentUserId)}>
            {user.avatarUrl ? <img src={user.avatarUrl} alt="profile" className="profile-chip-avatar" /> : <span>◯</span>}
            <span>{user.fullName}</span>
          </button>
          <button className="secondary" onClick={logout}>
            Logout
          </button>
        </div>

        <form className="group-creator" onSubmit={submitGroup}>
          <label>
            New group name
            <input value={groupName} onChange={(e) => setGroupName(e.target.value)} placeholder="Group name" />
          </label>
          <div className="member-picks">
            {users.map((u) => {
              const checked = groupMembers.includes(u.id);
              return (
                <label key={u.id} className="member-pick">
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setGroupMembers((prev) => [...prev, u.id]);
                      } else {
                        setGroupMembers((prev) => prev.filter((id) => id !== u.id));
                      }
                    }}
                  />
                  {u.fullName || u.username}
                </label>
              );
            })}
          </div>
          <button type="submit" disabled={!groupName.trim()}>
            Create Group
          </button>
        </form>

        <div className="nav-list">
          <p className="section-title">مخاطبین</p>
          {contactItems.map((item) => {
            const active = selected?.kind === item.kind && selected.id === item.id;
            return (
              <button
                type="button"
                key={`${item.kind}-${item.id}`}
                className={`nav-item ${active ? "active" : ""}`}
                onClick={() => onSelect(item)}
              >
                <span className="status-dot-inline">{item.online ? "●" : "○"}</span>
                {item.label}
              </button>
            );
          })}

          <p className="section-title">گروه‌ها</p>
          {groupItems.map((item) => {
            const active = selected?.kind === item.kind && selected.id === item.id;
            return (
              <button
                type="button"
                key={`${item.kind}-${item.id}`}
                className={`nav-item ${active ? "active" : ""}`}
                onClick={() => onSelect(item)}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </aside>

      <main className="conversation">
        <header className="conversation-header">
          <h3>{selected ? selected.label : "Select a chat"}</h3>
          {selected?.kind === "user" ? (
            <div className="header-actions">
              <span className="presence-badge">{onlineUserIds.includes(selected.id) ? "Online" : "Offline"}</span>
              <button type="button" className="secondary" onClick={() => void openProfile(selected.id)}>
                Profile
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() =>
                  selectedUserBlocked
                    ? void unblockUser(selected.id, currentUserId)
                    : void blockUser(selected.id, currentUserId)
                }
              >
                {selectedUserBlocked ? "Unblock" : "Block"}
              </button>
            </div>
          ) : null}
          {selectedGroup && selectedGroup.creator === currentUserId ? (
            <div className="header-actions">
              <select
                value={newMemberId}
                onChange={(e) => setNewMemberId(e.target.value ? Number(e.target.value) : "")}
              >
                <option value="">Select user</option>
                {users.map((entry) => (
                  <option key={entry.id} value={entry.id}>
                    {entry.fullName || entry.username}
                  </option>
                ))}
              </select>
              <button type="button" className="secondary" onClick={addMember} disabled={!newMemberId}>
                Add Member
              </button>
            </div>
          ) : null}
        </header>

        <section className="message-feed">
          {!selected ? <p className="placeholder">Choose a contact or group to start messaging.</p> : null}
          {typingVisible ? <p className="typing-note">User is typing...</p> : null}
          {error ? <p className="error">{error}</p> : null}
          {loading ? <LoadingState /> : null}

          {messages.map((msg) => {
            const mine = msg.from === currentUserId;
            return (
              <article key={msg.id ?? `${msg.from}-${msg.timestamp}`} className={`bubble ${mine ? "mine" : "their"}`}>
                {msg.content ? <p>{msg.content}</p> : null}
                {msg.mediaUrl && msg.mediaType === "image" ? <img className="media-preview" src={msg.mediaUrl} alt="image" /> : null}
                {msg.mediaUrl && msg.mediaType === "audio" ? <audio className="media-audio" src={msg.mediaUrl} controls /> : null}
                {msg.mediaUrl && msg.mediaType !== "image" && msg.mediaType !== "audio" ? (
                  <a className="media-link" href={msg.mediaUrl} target="_blank" rel="noreferrer">
                    Open file
                  </a>
                ) : null}
                {typeof msg.latitude === "number" && typeof msg.longitude === "number" ? (
                  <a
                    className="media-link"
                    href={`https://www.google.com/maps?q=${msg.latitude},${msg.longitude}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    View location
                  </a>
                ) : null}
              </article>
            );
          })}
        </section>

        <form className="composer" onSubmit={onSend}>
          <input
            ref={mediaInputRef}
            type="file"
            accept="image/*,video/*"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />
          <input
            ref={documentInputRef}
            type="file"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />

          <div className="composer-attach">
            <button
              type="button"
              className="icon-btn"
              onClick={() => setShowAttachMenu((prev) => !prev)}
              disabled={!selected}
              aria-label="Attach"
            >
              ⊕
            </button>

            {showAttachMenu && selected ? (
              <div className="attach-menu">
                <button type="button" className="attach-item" onClick={() => mediaInputRef.current?.click()}>
                  <span>▣</span>
                  <span>Photo or video</span>
                </button>
                <button type="button" className="attach-item" onClick={() => documentInputRef.current?.click()}>
                  <span>≣</span>
                  <span>Document</span>
                </button>
                <button type="button" className="attach-item" onClick={shareLocation}>
                  <span>⌖</span>
                  <span>Location</span>
                </button>
              </div>
            ) : null}
          </div>

          <input
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              void sendTyping(currentUserId);
            }}
            disabled={!selected}
            placeholder={selected ? "Type your message..." : "Select a chat first"}
          />

          <div className="emoji-wrap">
            <button
              type="button"
              className="icon-btn"
              onClick={() => setShowEmojiMenu((prev) => !prev)}
              disabled={!selected}
              aria-label="Emoji"
            >
              ◡
            </button>
            {showEmojiMenu && selected ? (
              <div className="emoji-menu">
                {emojiItems.map((emoji) => (
                  <button
                    key={emoji}
                    type="button"
                    className="emoji-item"
                    onClick={() => {
                      setDraft((prev) => `${prev}${emoji}`);
                      setShowEmojiMenu(false);
                    }}
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            ) : null}
          </div>
          <button
            type="button"
            className="icon-btn"
            onMouseDown={() => void startRecording()}
            onMouseUp={stopRecording}
            onMouseLeave={() => recording && stopRecording()}
            disabled={!selected}
            aria-label="Voice"
          >
            {recording ? "●" : "◉"}
          </button>
          <button type="submit" disabled={!selected || !draft.trim()} className="send-btn-min" aria-label="Send">
            ➤
          </button>
        </form>

        {showProfileModal && activeProfile ? (
          <div className="modal-overlay" onClick={() => setShowProfileModal(false)}>
            <div className="profile-modal" onClick={(e) => e.stopPropagation()}>
              <h4>Profile</h4>
              <form className="profile-form" onSubmit={onProfileSave}>
                <input ref={avatarInputRef} type="file" style={{ display: "none" }} onChange={onAvatarChange} />
                <div className="profile-avatar-row">
                  {profileAvatarUrl ? (
                    <img src={profileAvatarUrl} alt="avatar" className="profile-avatar" />
                  ) : (
                    <div className="profile-avatar profile-avatar-empty">◯</div>
                  )}
                  {isOwnProfile ? (
                    <button type="button" className="secondary" onClick={() => avatarInputRef.current?.click()}>
                      Change photo
                    </button>
                  ) : null}
                </div>

                <label>
                  ID
                  <input value={String(activeProfile.id)} disabled />
                </label>
                <label>
                  Username
                  <input value={profileUsername} onChange={(e) => setProfileUsername(e.target.value)} disabled={!isOwnProfile} />
                </label>
                <label>
                  Name
                  <input value={profileFullName} onChange={(e) => setProfileFullName(e.target.value)} disabled={!isOwnProfile} />
                </label>
                <label>
                  Bio
                  <input value={profileBio} onChange={(e) => setProfileBio(e.target.value)} disabled={!isOwnProfile} />
                </label>

                <div className="profile-actions">
                  <button type="button" className="secondary" onClick={() => setShowProfileModal(false)}>
                    Close
                  </button>
                  {isOwnProfile ? <button type="submit">Save</button> : null}
                </div>
              </form>
            </div>
          </div>
        ) : null}
      </main>
    </div>
  );
}
