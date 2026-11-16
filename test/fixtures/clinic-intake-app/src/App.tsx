import { Route, Routes } from "react-router-dom";
import Locations from "./pages/Locations";
import PatientDetail from "./pages/PatientDetail";
import Patients from "./pages/Patients";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Patients />} />
      <Route path="/patients/:id" element={<PatientDetail />} />
      <Route path="/locations" element={<Locations />} />
    </Routes>
  );
}
