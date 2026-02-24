/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        // Vamos definir nossa identidade "Dark & Secure" aqui
        bg: '#1a1b26',       // Fundo bem escuro (quase preto azulado)
        surface: '#24283b',  // Cor dos cartões/botões
        primary: '#7aa2f7',  // Azul destaque
        accent: '#bb9af7',   // Roxo suave para detalhes
        danger: '#f7768e',   // Vermelho para "Deletar"
        success: '#9ece6a',  // Verde para "Senha Forte"
      }
    },
  },
  plugins: [],
}