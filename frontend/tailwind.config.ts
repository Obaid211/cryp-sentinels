import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        surface: {
          DEFAULT: "var(--surface)",
          dim: "var(--surface-dim)",
          bright: "var(--surface-bright)",
          lowest: "var(--surface-container-lowest)",
          low: "var(--surface-container-low)",
          container: "var(--surface-container)",
          high: "var(--surface-container-high)",
          highest: "var(--surface-container-highest)",
          variant: "var(--surface-variant)",
        },
        primary: {
          DEFAULT: "var(--primary)",
          deep: "var(--primary-deep)",
          container: "var(--primary-container)",
          fixed: "var(--primary-fixed)",
          "fixed-dim": "var(--primary-fixed-dim)",
        },
        secondary: {
          DEFAULT: "var(--secondary)",
          muted: "var(--secondary-muted)",
          container: "var(--secondary-container)",
        },
        tertiary: {
          DEFAULT: "var(--tertiary)",
          dark: "var(--tertiary-dark)",
          container: "var(--tertiary-container)",
        },
        severity: {
          critical: "var(--severity-critical)",
          high: "var(--severity-high)",
          medium: "var(--severity-medium)",
          low: "var(--severity-low)",
          safe: "var(--severity-safe)",
        },
        outline: {
          dormant: "var(--border-dormant)",
          focused: "var(--border-focused)",
          active: "var(--border-active)",
        }
      },
      fontFamily: {
        display: ["var(--font-display)", "Syne", "sans-serif"],
        body: ["var(--font-body)", "Geist", "sans-serif"],
        mono: ["var(--font-mono)", "Geist Mono", "monospace"],
      },
      borderRadius: {
        none: "0px",
        DEFAULT: "0px",
        sm: "0px",
        md: "0px",
        lg: "0px",
        xl: "0px",
        "2xl": "0px",
        full: "0px",
      },
      boxShadow: {
        flat: "4px 4px 0px #111111",
        "flat-sm": "2px 2px 0px #111111",
        accent: "4px 4px 0px #ff3300",
      }
    },
  },
  plugins: [],
}

export default config
