# Build stage
FROM node:16-alpine as build

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Set environment variables for production build
ARG REACT_APP_USER_SERVICE_URL
ARG REACT_APP_PRODUCT_SERVICE_URL
ENV REACT_APP_USER_SERVICE_URL=${REACT_APP_USER_SERVICE_URL}
ENV REACT_APP_PRODUCT_SERVICE_URL=${REACT_APP_PRODUCT_SERVICE_URL}

# Build the application
RUN npm run build

# Production stage
FROM nginx:1.21-alpine

# Copy the build output to replace the default nginx contents
COPY --from=build /app/build /usr/share/nginx/html

# Copy the nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]