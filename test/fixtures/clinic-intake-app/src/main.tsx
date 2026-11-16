import posthog from "posthog-js";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

posthog.init(import.meta.env.VITE_POSTHOG_KEY, {
  api_host: "https://us.i.posthog.com",
  session_recording: { maskAllInputs: false },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
