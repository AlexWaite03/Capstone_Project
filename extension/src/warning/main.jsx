import { createRoot } from 'react-dom/client';
import { StrictMode } from 'react';
import Warning from './Warning.jsx';

const root = createRoot(document.getElementById('root'));
root.render(
  <StrictMode>
    <Warning />
  </StrictMode>
);
