import { Route, Routes } from "react-router-dom";
import Billing from "./pages/Billing";
import Leads from "./pages/Leads";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Leads />} />
      <Route path="/billing" element={<Billing />} />
    </Routes>
  );
}
