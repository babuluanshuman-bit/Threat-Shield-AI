import React from 'react';
import { CyberGuardProvider, useCyberGuard } from './context/CyberGuardContext';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { LiveAlertBanner } from './components/common/LiveAlertBanner';
import { GlobalSearchModal } from './components/common/GlobalSearchModal';
import { NotificationDrawer } from './components/common/NotificationDrawer';
import { CyberCopilotDrawer } from './components/copilot/CyberCopilotDrawer';
import { AttackSimulationModal } from './components/simulation/AttackSimulationModal';

// Pages
import { LandingPage } from './pages/LandingPage';
import { SocDashboard } from './pages/SocDashboard';
import { UrlAnalyzerPage } from './pages/UrlAnalyzerPage';
import { EmailAnalyzerPage } from './pages/EmailAnalyzerPage';
import { MessageAnalyzerPage } from './pages/MessageAnalyzerPage';
import { MediaAnalyzerPage } from './pages/MediaAnalyzerPage';
import { NetworkAnalyzerPage } from './pages/NetworkAnalyzerPage';
import { FileAnalyzerPage } from './pages/FileAnalyzerPage';
import { ThreatIntelligencePage } from './pages/ThreatIntelligencePage';
import { SecurityPosturePage } from './pages/SecurityPosturePage';

const AppContent: React.FC = () => {
  const { activeTab } = useCyberGuard();

  const renderActiveView = () => {
    switch (activeTab) {
      case 'landing':
        return <LandingPage />;
      case 'dashboard':
      case 'incidents':
        return <SocDashboard />;
      case 'url-scanner':
        return <UrlAnalyzerPage />;
      case 'email-scanner':
        return <EmailAnalyzerPage />;
      case 'message-scanner':
        return <MessageAnalyzerPage />;
      case 'media-scanner':
        return <MediaAnalyzerPage />;
      case 'network-threat':
        return <NetworkAnalyzerPage />;
      case 'file-scanner':
        return <FileAnalyzerPage />;
      case 'threat-intel':
        return <ThreatIntelligencePage />;
      case 'posture':
        return <SecurityPosturePage />;
      default:
        return <SocDashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-[#050811] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200 overflow-x-hidden">
      {/* Top Navbar */}
      <Navbar />

      {/* High-Priority Real-Time Threat Banner */}
      <LiveAlertBanner />

      {/* Main Content Layout */}
      {activeTab === 'landing' ? (
        <main className="flex-1 overflow-x-hidden">
          <LandingPage />
        </main>
      ) : (
        <div className="flex-1 flex overflow-hidden">
          {/* Left Navigation Sidebar */}
          <Sidebar />

          {/* Center Scrollable Work Area */}
          <main className="flex-1 overflow-y-auto overflow-x-hidden p-3 sm:p-5 lg:p-8 bg-[#050811]">
            {renderActiveView()}
          </main>
        </div>
      )}

      {/* Modals & Overlays */}
      <GlobalSearchModal />
      <NotificationDrawer />
      <CyberCopilotDrawer />
      <AttackSimulationModal />
    </div>
  );
};

export function App() {
  return (
    <CyberGuardProvider>
      <AppContent />
    </CyberGuardProvider>
  );
}

export default App;
