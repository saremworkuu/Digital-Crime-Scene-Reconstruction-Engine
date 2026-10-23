import React from 'react';
import { ShieldAlert, ArrowLeft, LogIn } from 'lucide-react';
import { useApp } from '../../store';

interface NoAccessProps {
  requiredRole?: string;
  onGoBack?: () => void;
}

export const NoAccess: React.FC<NoAccessProps> = ({
  requiredRole = 'admin',
  onGoBack
}) => {
  const { currentUser, setCurrentPage, theme } = useApp();
  const isLight = theme === 'light';

  const handleReturn = () => {
    if (typeof window !== 'undefined') {
      window.location.hash = '';
    }
    if (onGoBack) {
      onGoBack();
    } else {
      if (currentUser?.role === 'admin') {
        setCurrentPage('admin');
      } else if (currentUser?.role === 'investigator') {
        setCurrentPage('dashboard');
      } else {
        setCurrentPage('home');
      }
    }
  };

  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center p-6 text-center">
      <div className={`w-full max-w-md p-8 rounded-3xl backdrop-blur-xl space-y-5 border ${
        isLight ? 'bg-white border-red-200 shadow-xl' : 'bg-[#141211]/90 border-red-900/60 shadow-2xl'
      }`}>
        <div className={`w-16 h-16 mx-auto rounded-2xl flex items-center justify-center border shadow-md ${
          isLight ? 'bg-red-50 border-red-200 text-red-600' : 'bg-red-950/80 border-red-700/60 text-red-500 shadow-[0_0_25px_rgba(239,68,68,0.3)]'
        }`}>
          <ShieldAlert className="w-8 h-8" />
        </div>

        <div className="space-y-2">
          <span className={`text-[11px] font-mono uppercase tracking-widest font-bold px-2.5 py-1 rounded-md border ${
            isLight ? 'text-red-700 bg-red-50 border-red-200' : 'text-red-400 bg-red-950/60 border-red-800/40'
          }`}>
            Access Restricted
          </span>
          <h2 className={`text-xl sm:text-2xl font-black tracking-tight font-sans ${
            isLight ? 'text-slate-900' : 'text-white'
          }`}>
            Unauthorized Portal Zone
          </h2>
          <p className={`text-xs sm:text-sm font-sans leading-relaxed ${
            isLight ? 'text-slate-600' : 'text-stone-400'
          }`}>
            {currentUser
              ? `Your account (${currentUser.email}) has role "${currentUser.role}", which lacks permission to access the DCSRE Administration command console. Required: ${requiredRole.toUpperCase()}.`
              : 'You must be signed in with administrative credentials to access this console.'}
          </p>
        </div>

        <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-3">
          <button
            type="button"
            onClick={handleReturn}
            className={`w-full sm:w-auto px-4 py-2.5 rounded-xl text-xs font-semibold border transition-all flex items-center justify-center gap-2 cursor-pointer ${
              isLight
                ? 'text-slate-700 bg-slate-100 hover:bg-slate-200 border-slate-300'
                : 'text-stone-300 bg-stone-900 hover:bg-stone-800 border-stone-700'
            }`}
          >
            <ArrowLeft className="w-4 h-4" />
            <span>
              Return to {currentUser?.role === 'investigator' ? 'Investigator Dashboard' : currentUser?.role === 'admin' ? 'Admin Dashboard' : 'Home'}
            </span>
          </button>

          {!currentUser && (
            <button
              type="button"
              onClick={() => setCurrentPage('login')}
              className="w-full sm:w-auto px-5 py-2.5 rounded-xl text-xs font-bold text-white bg-[#f95721] hover:bg-[#ea580c] transition-all shadow-[0_0_15px_rgba(249,87,33,0.4)] flex items-center justify-center gap-2 cursor-pointer"
            >
              <LogIn className="w-4 h-4" />
              <span>Sign In as Admin</span>
            </button>
          )}
        </div>

        {/* Security Notice */}
        <p className={`text-[10px] font-mono pt-2 border-t ${
          isLight ? 'text-slate-400 border-slate-100' : 'text-stone-600 border-[#26201e]'
        }`}>
          SECURITY POLICY: Real authentication and role privileges must be strictly enforced on the server-side API.
        </p>
      </div>
    </div>
  );
};
