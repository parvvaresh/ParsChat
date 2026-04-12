import { Suspense, lazy, useEffect } from "react";
import { LoadingState } from "./components/LoadingState";
import { useAuthStore } from "./store";

const AuthView = lazy(() => import("./features/auth/AuthView").then((module) => ({ default: module.AuthView })));
const ChatView = lazy(() => import("./features/chat/ChatView").then((module) => ({ default: module.ChatView })));

export function App() {
  const { user, hydrate } = useAuthStore();

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  return (
    <Suspense fallback={<LoadingState label="Preparing application..." />}>
      {user ? <ChatView /> : <AuthView />}
    </Suspense>
  );
}