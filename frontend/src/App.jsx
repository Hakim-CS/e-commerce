import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import ProductList from './components/ProductList';
import { auth, user } from './api';

const App = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const authenticated = await auth.checkLogin();
      setIsAuthenticated(authenticated);
      
      if (authenticated) {
        const profile = await user.getProfile();
        setUserProfile(profile);
      }
    } catch (error) {
      console.error('Auth check error:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLoginSuccess = async (data) => {
    setIsAuthenticated(true);
    try {
      const profile = await user.getProfile();
      setUserProfile(profile);
    } catch (error) {
      console.error('Get profile error:', error);
    }
  };

  const handleLogout = async () => {
    await auth.logout();
    setIsAuthenticated(false);
    setUserProfile(null);
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div>
      <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
        <div className="container">
          <a className="navbar-brand" href="#">E-Commerce Microservices</a>
          
          {isAuthenticated && userProfile && (
            <div className="d-flex ms-auto text-white align-items-center">
              <span className="me-3">Welcome, {userProfile.first_name}</span>
              <button className="btn btn-outline-light" onClick={handleLogout}>
                Logout
              </button>
            </div>
          )}
        </div>
      </nav>

      <div className="container mt-4">
        {!isAuthenticated ? (
          <Login onLoginSuccess={handleLoginSuccess} />
        ) : (
          <ProductList />
        )}
      </div>
    </div>
  );
};

export default App;