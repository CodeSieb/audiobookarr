import React, { useState, useEffect, useCallback } from 'react';
import { Search, Download, Settings, Home, Clock, CheckCircle, XCircle, Eye, EyeOff, Trash2, Book, User, Calendar, FileText } from 'lucide-react';

// API service
const API_BASE = window.location.origin;

class ApiService {
  constructor() {
    this.token = localStorage.getItem('auth_token');
  }

  setToken(token) {
    this.token = token;
    localStorage.setItem('auth_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('auth_token');
  }

  getHeaders() {
    return {
      'Content-Type': 'application/json',
      ...(this.token && { 'Authorization': `Bearer ${this.token}` })
    };
  }

  async request(endpoint, options = {}) {
    try {
      const response = await fetch(`${API_BASE}/api${endpoint}`, {
        ...options,
        headers: { ...this.getHeaders(), ...options.headers }
      });

      if (response.status === 401) {
        this.clearToken();
        throw new Error('Authentication required');
      }

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Network error' }));
        throw new Error(error.detail || 'Request failed');
      }

      return response.json();
    } catch (error) {
      console.error('API request error:', error);
      throw error;
    }
  }

  async login(password) {
    const data = await this.request('/login', {
      method: 'POST',
      body: JSON.stringify({ password })
    });
    this.setToken(data.token);
    return data;
  }

  async search(query) {
    return this.request(`/search?q=${encodeURIComponent(query)}`);
  }

  async getLatest() {
    return this.request('/latest');
  }

  async addToQueue(book) {
    return this.request('/download', {
      method: 'POST',
      body: JSON.stringify(book)
    });
  }

  async getQueue() {
    return this.request('/queue');
  }

  async cancelDownload(queueId) {
    return this.request(`/queue/${queueId}`, { method: 'DELETE' });
  }

  async getSettings() {
    return this.request('/settings');
  }

  async updateSettings(settings) {
    return this.request('/settings', {
      method: 'POST',
      body: JSON.stringify(settings)
    });
  }

  async changePassword(oldPassword, newPassword) {
    const data = await this.request('/change-password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
    });
    this.setToken(data.token);
    return data;
  }
}

const api = new ApiService();

// WebSocket hook
function useWebSocket() {
  const [queue, setQueue] = useState([]);

  useEffect(() => {
    if (!api.token) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

    ws.onopen = () => {
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === 'queue_update') {
          setQueue(message.data);
        }
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected');
    };

    return () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.close();
      }
    };
  }, [api.token]);

  return queue;
}

// Components
function LoginScreen({ onLogin }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await api.login(password);
      onLogin();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-lg p-8 w-full max-w-md">
        <h1 className="text-2xl font-bold text-white mb-6 text-center">
          TokyBook Downloader
        </h1>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <input
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full p-3 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
              required
            />
          </div>
          {error && (
            <div className="mb-4 p-3 bg-red-600 text-white rounded-lg text-sm">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full p-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white rounded-lg font-semibold transition-colors"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}

function BookCard({ book, onDownload, showDownloadButton = true }) {
  const [downloading, setDownloading] = useState(false);

  const handleDownload = async () => {
    if (downloading) return;
    
    setDownloading(true);
    try {
      await onDownload(book);
    } catch (err) {
      alert(err.message);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 hover:bg-gray-750 transition-colors">
      <div className="flex space-x-4">
        {book.cover_image && (
          <img
            src={book.cover_image}
            alt={book.title}
            className="w-20 h-28 object-cover rounded flex-shrink-0"
          />
        )}
        <div className="flex-1 min-w-0">
          <h3 className="font-semibold text-white text-sm mb-1 line-clamp-2">
            {book.title}
          </h3>
          {book.author && (
            <p className="text-gray-400 text-xs mb-1 flex items-center">
              <User className="w-3 h-3 mr-1" />
              {book.author}
            </p>
          )}
          {book.series && (
            <p className="text-gray-400 text-xs mb-1 flex items-center">
              <Book className="w-3 h-3 mr-1" />
              {book.series}
            </p>
          )}
          {book.published_date && (
            <p className="text-gray-400 text-xs mb-2 flex items-center">
              <Calendar className="w-3 h-3 mr-1" />
              {book.published_date}
            </p>
          )}
          {book.description && (
            <p className="text-gray-300 text-xs line-clamp-2 mb-2">
              {book.description}
            </p>
          )}
          {showDownloadButton && (
            <button
              onClick={handleDownload}
              disabled={downloading}
              className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white p-2 rounded text-sm font-medium transition-colors flex items-center justify-center"
            >
              <Download className="w-4 h-4 mr-2" />
              {downloading ? 'Adding...' : 'Download'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function HomeTab() {
  const [latest, setLatest] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadLatest();
  }, []);

  const loadLatest = async () => {
    try {
      const data = await api.getLatest();
      setLatest(data.results);
    } catch (err) {
      console.error('Failed to load latest:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (book) => {
    await api.addToQueue(book);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-400">Loading latest uploads...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-white mb-4">Latest Uploads</h2>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {latest.map((book, index) => (
          <BookCard
            key={index}
            book={book}
            onDownload={handleDownload}
          />
        ))}
      </div>
    </div>
  );
}

function SearchTab() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setHasSearched(true);
    try {
      const data = await api.search(query);
      setResults(data.results);
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (book) => {
    await api.addToQueue(book);
  };

  return (
    <div className="space-y-4">
      <form onSubmit={handleSearch} className="flex space-x-2">
        <input
          type="text"
          placeholder="Search for audiobooks..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="flex-1 p-3 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white rounded-lg font-semibold transition-colors flex items-center"
        >
          <Search className="w-4 h-4 mr-2" />
          {loading ? 'Searching...' : 'Search'}
        </button>
      </form>

      {results.length > 0 && (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {results.map((book, index) => (
            <BookCard
              key={index}
              book={book}
              onDownload={handleDownload}
            />
          ))}
        </div>
      )}

      {!loading && hasSearched && results.length === 0 && (
        <div className="text-center text-gray-400 py-8">
          No results found for "{query}"
        </div>
      )}
    </div>
  );
}

function QueueTab({ queue }) {
  const handleCancel = async (queueId) => {
    try {
      await api.cancelDownload(queueId);
    } catch (err) {
      alert(err.message);
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'waiting':
        return <Clock className="w-4 h-4 text-yellow-500" />;
      case 'downloading':
        return <Download className="w-4 h-4 text-blue-500" />;
      case 'completed':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return null;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-bold text-white mb-4">Download Queue</h2>
      
      {queue.length === 0 ? (
        <div className="text-center text-gray-400 py-8">
          No downloads in queue
        </div>
      ) : (
        <div className="space-y-3">
          {queue.map((item) => (
            <div key={item.id} className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  {getStatusIcon(item.status)}
                  <h3 className="font-semibold text-white text-sm">
                    {item.title}
                  </h3>
                </div>
                {(item.status === 'waiting' || item.status === 'failed') && (
                  <button
                    onClick={() => handleCancel(item.id)}
                    className="p-1 text-red-400 hover:text-red-300 transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
              
              {item.author && (
                <p className="text-gray-400 text-xs mb-1">
                  Author: {item.author}
                </p>
              )}
              
              {item.series && (
                <p className="text-gray-400 text-xs mb-1">
                  Series: {item.series}
                </p>
              )}
              
              <p className="text-gray-400 text-xs mb-2">
                Added: {formatDate(item.created_at)}
              </p>
              
              {item.status === 'downloading' && (
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${item.progress}%` }}
                  ></div>
                </div>
              )}
              
              <div className="flex items-center justify-between text-xs">
                                <span className={`capitalize font-medium ${
                  item.status === 'completed' ? 'text-green-400' :
                  item.status === 'failed' ? 'text-red-400' :
                  item.status === 'downloading' ? 'text-blue-400' :
                  'text-yellow-400'
                }`}>
                  {item.status}
                </span>
                {item.status === 'downloading' && (
                  <span className="text-gray-400">
                    {item.progress.toFixed(1)}%
                  </span>
                )}
                {item.completed_at && (
                  <span className="text-gray-400">
                    Completed: {formatDate(item.completed_at)}
                  </span>
                )}
              </div>
              
              {item.error_message && (
                <div className="mt-2 p-2 bg-red-900 bg-opacity-50 rounded text-red-300 text-xs">
                  Error: {item.error_message}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SettingsTab() {
  const [settings, setSettings] = useState({
    google_books_api_key: '',
    audiobookshelf_url: '',
    audiobookshelf_token: '',
    auto_refresh: true
  });
  const [passwordData, setPasswordData] = useState({
    old_password: '',
    new_password: '',
    confirm_password: ''
  });
  const [showPasswords, setShowPasswords] = useState({
    old: false,
    new: false,
    confirm: false
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const data = await api.getSettings();
      setSettings(data);
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSettings = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.updateSettings(settings);
      alert('Settings saved successfully!');
    } catch (err) {
      alert(err.message);
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    
    if (passwordData.new_password !== passwordData.confirm_password) {
      alert('New passwords do not match');
      return;
    }

    setChangingPassword(true);
    try {
      await api.changePassword(passwordData.old_password, passwordData.new_password);
      alert('Password changed successfully!');
      setPasswordData({ old_password: '', new_password: '', confirm_password: '' });
    } catch (err) {
      alert(err.message);
    } finally {
      setChangingPassword(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-gray-400">Loading settings...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-white mb-4">Settings</h2>
      
      {/* API Settings */}
      <form onSubmit={handleSaveSettings} className="bg-gray-800 rounded-lg p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white mb-4">API Configuration</h3>
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Google Books API Key
          </label>
          <input
            type="password"
            placeholder="Enter your Google Books API key"
            value={settings.google_books_api_key}
            onChange={(e) => setSettings({...settings, google_books_api_key: e.target.value})}
            className="w-full p-3 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
          <p className="text-xs text-gray-400 mt-1">
            Used to fetch book metadata and covers
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Audiobookshelf URL
          </label>
          <input
            type="url"
            placeholder="http://your-audiobookshelf-server:13378"
            value={settings.audiobookshelf_url}
            onChange={(e) => setSettings({...settings, audiobookshelf_url: e.target.value})}
            className="w-full p-3 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Audiobookshelf API Token
          </label>
          <input
            type="password"
            placeholder="Enter your Audiobookshelf API token"
            value={settings.audiobookshelf_token}
            onChange={(e) => setSettings({...settings, audiobookshelf_token: e.target.value})}
            className="w-full p-3 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center">
          <input
            type="checkbox"
            id="auto_refresh"
            checked={settings.auto_refresh}
            onChange={(e) => setSettings({...settings, auto_refresh: e.target.checked})}
            className="w-4 h-4 text-blue-600 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
          />
          <label htmlFor="auto_refresh" className="ml-2 text-sm text-gray-300">
            Auto-refresh Audiobookshelf library after downloads
          </label>
        </div>

        <button
          type="submit"
          disabled={saving}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 text-white p-3 rounded-lg font-semibold transition-colors"
        >
          {saving ? 'Saving...' : 'Save Settings'}
        </button>
      </form>

      {/* Password Change */}
      <form onSubmit={handleChangePassword} className="bg-gray-800 rounded-lg p-6 space-y-4">
        <h3 className="text-lg font-semibold text-white mb-4">Change Password</h3>
        
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Current Password
          </label>
          <div className="relative">
            <input
              type={showPasswords.old ? "text" : "password"}
              placeholder="Enter current password"
              value={passwordData.old_password}
              onChange={(e) => setPasswordData({...passwordData, old_password: e.target.value})}
              className="w-full p-3 pr-10 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
              required
            />
            <button
              type="button"
              onClick={() => setShowPasswords({...showPasswords, old: !showPasswords.old})}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
            >
              {showPasswords.old ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            New Password
          </label>
          <div className="relative">
            <input
              type={showPasswords.new ? "text" : "password"}
              placeholder="Enter new password"
              value={passwordData.new_password}
              onChange={(e) => setPasswordData({...passwordData, new_password: e.target.value})}
              className="w-full p-3 pr-10 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
              required
            />
            <button
              type="button"
              onClick={() => setShowPasswords({...showPasswords, new: !showPasswords.new})}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
            >
              {showPasswords.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            Confirm New Password
          </label>
          <div className="relative">
            <input
              type={showPasswords.confirm ? "text" : "password"}
              placeholder="Confirm new password"
              value={passwordData.confirm_password}
              onChange={(e) => setPasswordData({...passwordData, confirm_password: e.target.value})}
              className="w-full p-3 pr-10 bg-gray-700 text-white rounded-lg border border-gray-600 focus:border-blue-500 focus:outline-none"
              required
            />
            <button
              type="button"
              onClick={() => setShowPasswords({...showPasswords, confirm: !showPasswords.confirm})}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-300"
            >
              {showPasswords.confirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <button
          type="submit"
          disabled={changingPassword}
          className="w-full bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white p-3 rounded-lg font-semibold transition-colors"
        >
          {changingPassword ? 'Changing Password...' : 'Change Password'}
        </button>
      </form>
    </div>
  );
}

// Main App Component
export default function TokyBookDownloader() {
  const [authenticated, setAuthenticated] = useState(!!api.token);
  const [activeTab, setActiveTab] = useState('home');
  const queue = useWebSocket();

  const handleLogin = () => {
    setAuthenticated(true);
  };

  const handleLogout = () => {
    api.clearToken();
    setAuthenticated(false);
  };

  if (!authenticated) {
    return <LoginScreen onLogin={handleLogin} />;
  }

  const tabs = [
    { id: 'home', label: 'Home', icon: Home },
    { id: 'search', label: 'Search', icon: Search },
    { id: 'queue', label: 'Queue', icon: Download, badge: queue.filter(item => item.status === 'downloading').length },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-4 py-3">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <h1 className="text-xl font-bold text-white flex items-center">
            <FileText className="w-6 h-6 mr-2" />
            TokyBook Downloader
          </h1>
          <button
            onClick={handleLogout}
            className="text-gray-400 hover:text-white transition-colors"
          >
            Logout
          </button>
        </div>
      </header>

      <div className="max-w-7xl mx-auto flex">
        {/* Sidebar */}
        <nav className="w-64 bg-gray-800 min-h-screen p-4">
          <ul className="space-y-2">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <li key={tab.id}>
                  <button
                    onClick={() => setActiveTab(tab.id)}
                    className={`w-full flex items-center px-4 py-3 rounded-lg transition-colors ${
                      isActive
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                    }`}
                  >
                    <Icon className="w-5 h-5 mr-3" />
                    {tab.label}
                    {tab.badge > 0 && (
                      <span className="ml-auto bg-red-500 text-white text-xs px-2 py-1 rounded-full">
                        {tab.badge}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {activeTab === 'home' && <HomeTab />}
          {activeTab === 'search' && <SearchTab />}
          {activeTab === 'queue' && <QueueTab queue={queue} />}
          {activeTab === 'settings' && <SettingsTab />}
        </main>
      </div>
    </div>
  );
}