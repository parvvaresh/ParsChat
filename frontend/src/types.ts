export type ApiError = {
  error: string;
  code?: string;
};

export type User = {
  id: number;
  username: string;
  fullName: string;
  bio?: string;
  avatarUrl?: string;
  token?: string;
};

export type Group = {
  id: number;
  name: string;
  creator: number;
};

export type Message = {
  id?: number;
  type: "message";
  content?: string;
  from: number;
  to?: number;
  groupId?: number;
  mediaUrl?: string;
  mediaType?: string;
  latitude?: number;
  longitude?: number;
  timestamp?: number;
};

export type SendMessageRequest = {
  from: number;
  to?: number;
  groupId?: number;
  content?: string;
  mediaUrl?: string;
  mediaType?: string;
  latitude?: number;
  longitude?: number;
};

export type ChatTarget =
  | { kind: "user"; id: number; label: string }
  | { kind: "group"; id: number; label: string };

export type TypingEvent = {
  type: "typing";
  from: number;
};

export type OnlineEvent = {
  type: "user_online" | "user_offline";
  userId: number;
};

export type ConnectedEvent = {
  type: "connected";
};

export type RealtimeEvent = Message | TypingEvent | OnlineEvent | ConnectedEvent;