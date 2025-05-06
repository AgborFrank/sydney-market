
module.exports = {
    content: [
      './templates/**/*.html',  // Adjust path to your templates
    ],
    theme: {
      extend: {
        colors: {
          primary: 'var(--primary-color)',    // Use CSS variables
          secondary: 'var(--secondary-color)',
        },
      },
    },
    plugins: [],
  };