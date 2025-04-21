/** @type {import('tailwindcss').Config} */
export default {
	content: [
		"./index.html",
		"./main.js", // Scan JS for potential classes if needed
		// Add other template paths if necessary
	],
	theme: {
		extend: {},
	},
	plugins: [require("@tailwindcss/typography")],
	darkMode: "selector", // Enable dark mode via class
};
