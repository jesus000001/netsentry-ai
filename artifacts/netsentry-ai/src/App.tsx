import { type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import Overview from '@/pages/overview';
import Traffic from '@/pages/traffic';
import Snort from '@/pages/snort';
import Logs from '@/pages/logs';
import AiModel from '@/pages/ai-model';
import Analysis from '@/pages/analysis';
import Machines from '@/pages/machines';
import Auth from '@/pages/auth';
import { WorkspaceShell } from '@/components/netsentry-shell';
import {
  Route,
  Switch,
  useLocation,
  Router as WouterRouter,
} from 'wouter';

const queryClient = new QueryClient();

function Router() {
  return (
    <RoutedErrorBoundary>
      <Switch>
        <Route path="/login"><Auth mode="login" /></Route>
        <Route path="/register"><Auth mode="register" /></Route>
        <Route path="/forgot-password"><Auth mode="forgot" /></Route>
        <Route path="/reset-password"><Auth mode="reset" /></Route>
        <Route>
          <WorkspaceShell>
            <Switch>
              <Route path="/" component={Overview} />
              <Route path="/traffic" component={Traffic} />
              <Route path="/snort" component={Snort} />
              <Route path="/logs" component={Logs} />
              <Route path="/ai-model" component={AiModel} />
              <Route path="/analysis" component={Analysis} />
              <Route path="/machines" component={Machines} />
              <Route component={NotFound} />
            </Switch>
          </WorkspaceShell>
        </Route>
      </Switch>
    </RoutedErrorBoundary>
  );
}

function RoutedErrorBoundary({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  return <ErrorBoundary resetKey={location}>{children}</ErrorBoundary>;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
