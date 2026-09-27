
import React, {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react";

import api from "../api";

const AuthContext = createContext(null);

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Restore the session when the page refreshes
  useEffect(() => {
    let active = true;

    async function fetchProfile() {
      try {
        const response = await api.get("/profile");

        if (active) {
          if (response.data.email) {
            setUser({
              name: response.data.name,
              email: response.data.email,
            });
          } else {
            setUser(null);
          }
        }
      } catch (err) {
        if (active) {
          setUser(null);

          // 401 simply means the user is not logged in
          if (err.response?.status !== 401) {
            console.error(
              "Profile request failed:",
              err.message
            );
          }
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    fetchProfile();

    return () => {
      active = false;
    };
  }, []);

  // Register a new user
  async function register(
    name,
    email,
    password,
    confirmPassword
  ) {
    setError("");

    try {
      const response = await api.post("/register", {
        name,
        email,
        password,
        confirmPassword,
      });

      if (response.data.success) {
        setUser(response.data.user);

        return {
          success: true,
          user: response.data.user,
          message: "Registration successful!",
        };
      }

      const message =
        response.data.message || "Registration failed";

      setError(message);
      alert(message);

      return {
        success: false,
        message,
      };
    } catch (err) {
      const message =
        err.response?.data?.message ||
        (err.code === "ERR_NETWORK"
          ? "Cannot connect to the backend server."
          : "An error occurred during registration.");

      setError(message);
      alert(message);

      console.error("Registration error:", err.message);

      return {
        success: false,
        message,
      };
    }
  }

  // Login
  async function login(email, password) {
    setError("");

    try {
      const response = await api.post("/login", {
        email,
        password,
      });

      if (response.data.success) {
        setUser(response.data.user);

        return {
          success: true,
          user: response.data.user,
          message: "Login successful!",
        };
      }

      const message =
        response.data.message || "Login failed";

      setError(message);
      alert(message);

      return {
        success: false,
        message,
      };
    } catch (err) {
      const message =
        err.response?.data?.message ||
        (err.code === "ERR_NETWORK"
          ? "Cannot connect to the backend server."
          : "An error occurred during login.");

      setError(message);
      alert(message);

      console.error("Login error:", err.message);

      return {
        success: false,
        message,
      };
    }
  }

  // Logout
  async function logout() {
    setError("");

    try {
      const response = await api.post("/logout");

      if (response.data.success) {
        setUser(null);

        return {
          success: true,
          message: "Logged out successfully!",
        };
      }

      const message =
        response.data.message || "Logout failed";

      setError(message);

      return {
        success: false,
        message,
      };
    } catch (err) {
      const message =
        err.response?.data?.message ||
        "Unable to log out. Please try again.";

      setError(message);

      console.error("Logout error:", err.message);

      return {
        success: false,
        message,
      };
    }
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        setUser,
        loading,
        error,
        setError,
        register,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// Custom authentication hook
function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used inside AuthProvider"
    );
  }

  return context;
}

export { AuthProvider, useAuth };