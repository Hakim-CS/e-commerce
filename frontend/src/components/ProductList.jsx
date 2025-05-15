import React, { useState, useEffect } from 'react';
import { products, cart } from '../api';

const ProductList = () => {
  const [productList, setProductList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [addingToCart, setAddingToCart] = useState({});

  useEffect(() => {
    fetchProducts();
  }, []);

  const fetchProducts = async () => {
    try {
      setLoading(true);
      setError('');
      const data = await products.getAll();
      setProductList(data.items || []);
      setLoading(false);
    } catch (error) {
      setError('Failed to load products. Please try again later.');
      setLoading(false);
      console.error('Error fetching products:', error);
    }
  };

  const handleAddToCart = async (productId) => {
    setAddingToCart(prev => ({ ...prev, [productId]: true }));
    try {
      await cart.addProduct(productId, 1);
      setAddingToCart(prev => ({ ...prev, [productId]: false }));
      alert('Product added to cart successfully!');
    } catch (error) {
      setAddingToCart(prev => ({ ...prev, [productId]: false }));
      console.error('Error adding to cart:', error);
      alert('Failed to add product to cart. Please try again.');
    }
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center my-5">
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger my-3" role="alert">
        {error}
      </div>
    );
  }

  return (
    <div className="container my-4">
      <h2 className="mb-4">Products</h2>
      
      {productList.length === 0 ? (
        <div className="alert alert-info">No products available.</div>
      ) : (
        <div className="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
          {productList.map(product => (
            <div className="col" key={product.id}>
              <div className="card h-100">
                <div className="card-body">
                  <h5 className="card-title">{product.name}</h5>
                  <h6 className="card-subtitle mb-2 text-muted">SKU: {product.sku}</h6>
                  <p className="card-text">{product.description}</p>
                  <div className="d-flex justify-content-between align-items-center">
                    <span className="fs-5 fw-bold">${product.price.toFixed(2)}</span>
                    <span className={`badge ${product.stock > 10 ? 'bg-success' : product.stock > 0 ? 'bg-warning text-dark' : 'bg-danger'}`}>
                      {product.stock > 10 ? 'In Stock' : product.stock > 0 ? `Only ${product.stock} left` : 'Out of Stock'}
                    </span>
                  </div>
                </div>
                <div className="card-footer bg-transparent">
                  <button 
                    className="btn btn-primary w-100" 
                    onClick={() => handleAddToCart(product.id)}
                    disabled={product.stock === 0 || addingToCart[product.id]}
                  >
                    {addingToCart[product.id] ? (
                      <span>
                        <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                        Adding...
                      </span>
                    ) : (
                      'Add to Cart'
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default ProductList;