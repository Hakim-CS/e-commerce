/**
 * API client for interacting with the e-commerce microservices
 */

// Base URLs for the services
const USER_SERVICE_URL = process.env.REACT_APP_USER_SERVICE_URL || 'http://localhost:5000';
const PRODUCT_SERVICE_URL = process.env.REACT_APP_PRODUCT_SERVICE_URL || 'http://localhost:5000';

// Helper function to get the stored tokens
const getTokens = () => {
  const accessToken = localStorage.getItem('access_token');
  const refreshToken = localStorage.getItem('refresh_token');
  return { accessToken, refreshToken };
};

// Helper function to store the tokens
const storeTokens = (accessToken, refreshToken) => {
  localStorage.setItem('access_token', accessToken);
  localStorage.setItem('refresh_token', refreshToken);
};

// Helper function to clear the tokens
const clearTokens = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
};

// Generic fetch with authorization header
const fetchWithAuth = async (url, options = {}) => {
  const { accessToken } = getTokens();
  
  const headers = {
    ...options.headers,
    'Content-Type': 'application/json',
  };
  
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }
  
  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });
    
    // If the request was unauthorized, try to refresh the token
    if (response.status === 401) {
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Retry the request with the new token
        const { accessToken: newToken } = getTokens();
        headers['Authorization'] = `Bearer ${newToken}`;
        return fetch(url, {
          ...options,
          headers,
        });
      } else {
        // Refresh failed, user needs to log in again
        clearTokens();
        window.location.href = '/login';
        throw new Error('Session expired. Please log in again.');
      }
    }
    
    return response;
  } catch (error) {
    console.error('API request failed:', error);
    throw error;
  }
};

// Refresh the access token using the refresh token
const refreshAccessToken = async () => {
  const { refreshToken } = getTokens();
  
  if (!refreshToken) {
    return false;
  }
  
  try {
    const response = await fetch(`${USER_SERVICE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${refreshToken}`,
        'Content-Type': 'application/json',
      },
    });
    
    if (response.ok) {
      const data = await response.json();
      storeTokens(data.access_token, data.refresh_token || refreshToken);
      return true;
    } else {
      clearTokens();
      return false;
    }
  } catch (error) {
    console.error('Token refresh failed:', error);
    clearTokens();
    return false;
  }
};

// Authentication methods
export const auth = {
  // Log in and get tokens
  login: async (username, password) => {
    try {
      const response = await fetch(`${USER_SERVICE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      
      if (response.ok) {
        const data = await response.json();
        storeTokens(data.access_token, data.refresh_token);
        return data;
      } else {
        const error = await response.json();
        throw new Error(error.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      throw error;
    }
  },
  
  // Log out
  logout: async () => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/auth/logout`, {
        method: 'POST',
      });
      
      clearTokens();
      return response.ok;
    } catch (error) {
      console.error('Logout error:', error);
      clearTokens();
      return false;
    }
  },
  
  // Check if the user is logged in
  checkLogin: async () => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/auth/checkLogin`);
      
      if (response.ok) {
        const data = await response.json();
        return data.authenticated;
      }
      return false;
    } catch (error) {
      console.error('Check login error:', error);
      return false;
    }
  },
};

// User methods
export const user = {
  // Get current user profile
  getProfile: async () => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/user/profile`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get user profile');
      }
    } catch (error) {
      console.error('Get profile error:', error);
      throw error;
    }
  },
  
  // Update current user profile
  updateProfile: async (profileData) => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/user/profile`, {
        method: 'PUT',
        body: JSON.stringify(profileData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to update user profile');
      }
    } catch (error) {
      console.error('Update profile error:', error);
      throw error;
    }
  },
  
  // Change password
  changePassword: async (oldPassword, newPassword) => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/user/changePassword`, {
        method: 'PUT',
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      });
      
      return response.ok;
    } catch (error) {
      console.error('Change password error:', error);
      throw error;
    }
  },
  
  // Get user addresses
  getAddresses: async () => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/address`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get user addresses');
      }
    } catch (error) {
      console.error('Get addresses error:', error);
      throw error;
    }
  },
  
  // Create new address
  createAddress: async (addressData) => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/address`, {
        method: 'POST',
        body: JSON.stringify(addressData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to create address');
      }
    } catch (error) {
      console.error('Create address error:', error);
      throw error;
    }
  },
  
  // Get user contacts
  getContacts: async () => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/contact`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get user contacts');
      }
    } catch (error) {
      console.error('Get contacts error:', error);
      throw error;
    }
  },
  
  // Create new contact
  createContact: async (contactData) => {
    try {
      const response = await fetchWithAuth(`${USER_SERVICE_URL}/contact`, {
        method: 'POST',
        body: JSON.stringify(contactData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to create contact');
      }
    } catch (error) {
      console.error('Create contact error:', error);
      throw error;
    }
  },
};

// Product methods
export const products = {
  // Get all products
  getAll: async (page = 1, perPage = 10) => {
    try {
      const response = await fetch(`${PRODUCT_SERVICE_URL}/product?page=${page}&per_page=${perPage}`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get products');
      }
    } catch (error) {
      console.error('Get products error:', error);
      throw error;
    }
  },
  
  // Get product by ID
  getById: async (productId) => {
    try {
      const response = await fetch(`${PRODUCT_SERVICE_URL}/product/${productId}`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get product');
      }
    } catch (error) {
      console.error('Get product error:', error);
      throw error;
    }
  },
  
  // Create product (admin only)
  create: async (productData) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/product`, {
        method: 'POST',
        body: JSON.stringify(productData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to create product');
      }
    } catch (error) {
      console.error('Create product error:', error);
      throw error;
    }
  },
  
  // Update product (admin only)
  update: async (productId, productData) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/product/${productId}`, {
        method: 'PUT',
        body: JSON.stringify(productData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to update product');
      }
    } catch (error) {
      console.error('Update product error:', error);
      throw error;
    }
  },
  
  // Delete product (admin only)
  delete: async (productId) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/product/${productId}`, {
        method: 'DELETE',
      });
      
      return response.ok;
    } catch (error) {
      console.error('Delete product error:', error);
      throw error;
    }
  },
};

// Cart methods
export const cart = {
  // Get cart
  get: async () => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/cart`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get cart');
      }
    } catch (error) {
      console.error('Get cart error:', error);
      throw error;
    }
  },
  
  // Add product to cart
  addProduct: async (productId, quantity = 1) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/cart/add/${productId}`, {
        method: 'POST',
        body: JSON.stringify({ quantity }),
      });
      
      return response.ok;
    } catch (error) {
      console.error('Add to cart error:', error);
      throw error;
    }
  },
  
  // Update cart item quantity
  updateItem: async (itemId, action) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/cart/update/${itemId}`, {
        method: 'POST',
        body: JSON.stringify({ action }),
      });
      
      return response.ok;
    } catch (error) {
      console.error('Update cart item error:', error);
      throw error;
    }
  },
  
  // Remove item from cart
  removeItem: async (itemId) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/cart/remove/${itemId}`, {
        method: 'POST',
      });
      
      return response.ok;
    } catch (error) {
      console.error('Remove from cart error:', error);
      throw error;
    }
  },
  
  // Clear cart
  clear: async () => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/cart/clear`, {
        method: 'POST',
      });
      
      return response.ok;
    } catch (error) {
      console.error('Clear cart error:', error);
      throw error;
    }
  },
};

// Order methods
export const orders = {
  // Get all orders
  getAll: async () => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/order`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get orders');
      }
    } catch (error) {
      console.error('Get orders error:', error);
      throw error;
    }
  },
  
  // Get order by ID
  getById: async (orderId) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/order/${orderId}`);
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to get order');
      }
    } catch (error) {
      console.error('Get order error:', error);
      throw error;
    }
  },
  
  // Create order
  create: async (orderData) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/order`, {
        method: 'POST',
        body: JSON.stringify(orderData),
      });
      
      if (response.ok) {
        return response.json();
      } else {
        throw new Error('Failed to create order');
      }
    } catch (error) {
      console.error('Create order error:', error);
      throw error;
    }
  },
  
  // Cancel order
  cancel: async (orderId) => {
    try {
      const response = await fetchWithAuth(`${PRODUCT_SERVICE_URL}/order/${orderId}/cancel`, {
        method: 'POST',
      });
      
      return response.ok;
    } catch (error) {
      console.error('Cancel order error:', error);
      throw error;
    }
  },
};

export default {
  auth,
  user,
  products,
  cart,
  orders,
};