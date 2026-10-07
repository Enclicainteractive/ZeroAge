import React from 'react';
import { createRoot } from 'react-dom/client';
import AgeAssurance from '../AgeAssurance.jsx';
import AdminPolicy from '../AdminPolicy.jsx';
import './style.css';

const Surface = window.location.pathname.startsWith('/admin') ? AdminPolicy : AgeAssurance;
createRoot(document.getElementById('root')).render(<React.StrictMode><Surface /></React.StrictMode>);
