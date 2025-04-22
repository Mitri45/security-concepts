import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";
// https://vite.dev/config/
export default defineConfig({
	plugins: [tailwindcss()],
	server: {
		port: 3000,
	},
	build: {
		outDir: 'dist', 
	},
	base: './'
});
