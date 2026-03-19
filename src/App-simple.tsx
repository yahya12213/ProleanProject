import React from "react";

// Simple App component without complex providers to test React initialization
const App: React.FC = () => {
  console.log("App component rendering...");
  
  return (
    <div className="min-h-screen bg-background text-foreground">
      <h1 className="text-2xl font-bold p-8">PROLEAN Formation</h1>
      <p className="p-8">Site en cours de chargement...</p>
    </div>
  );
};

export default App;