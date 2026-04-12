import { FormEvent, useState } from "react";
import { useAuthStore } from "../../store";

export function AuthView() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");

  const { login, register, loading, error } = useAuthStore();

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (mode === "login") {
      await login(username, password);
      return;
    }

    const ok = await register(username, fullName, password);
    if (ok) {
      setMode("login");
      setPassword("");
    }
  };

  return (
    <div className="auth-screen">
      <form className="auth-card" onSubmit={submit}>
        <h1>ParsChat</h1>
        <p className="subtitle">Production-ready chat client</p>

        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} required />
        </label>

        {mode === "register" ? (
          <label>
            Full name
            <input value={fullName} onChange={(e) => setFullName(e.target.value)} required />
          </label>
        ) : null}

        <label>
          Password
          <input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            required
          />
        </label>

        {error ? <p className="error">{error}</p> : null}

        <button disabled={loading} type="submit">
          {loading ? "Please wait..." : mode === "login" ? "Login" : "Register"}
        </button>

        <p className="switch-mode">
          {mode === "login" ? "New user?" : "Already registered?"}{" "}
          <button
            type="button"
            className="link-btn"
            onClick={() => setMode(mode === "login" ? "register" : "login")}
          >
            {mode === "login" ? "Create account" : "Login"}
          </button>
        </p>
      </form>
    </div>
  );
}
