/** @type {import('tailwindcss').Config} */
const defaultTheme = require('tailwindcss/defaultTheme');
module.exports = {
  content: ['./templates/*.gohtml'],
  theme: {
    fontFamily: {
      'sans': [...defaultTheme.fontFamily.sans, '"Font Awesome 6 Pro"']
    },
    extend: {},
  },
  plugins: [
    require('@tailwindcss/aspect-ratio'),
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
};
