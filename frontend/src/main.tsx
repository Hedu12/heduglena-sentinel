import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App, createQueryClient } from "./app/App";
import "./styles/tokens.css";
import "./styles/app.css";

const root = document.getElementById("root");
if (root === null) throw new Error("missing #root element");

const queryClient = createQueryClient();
createRoot(root).render(
  <StrictMode>
    <App queryClient={queryClient} />
  </StrictMode>,
);
