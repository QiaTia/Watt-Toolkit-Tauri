import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import Components from 'unplugin-vue-components/vite';
import { AntDesignVueResolver } from 'unplugin-vue-components/resolvers';
import { fileURLToPath, URL } from 'node:url';

// Tauri 开发环境固定端口（与 tauri.conf.json devUrl 一致）
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [
    vue(),
    // ant-design-vue 按需引入：模板里直接写 <a-card> / <SearchOutlined /> 即可，
    // 编译期自动补 import，未用到的组件不进包。
    // importStyle 必须为 false —— v4 起样式由 CSS-in-JS 运行时注入，
    // 开启后插件会去找并不存在的 `es/xxx/style/css` 目录导致构建失败。
    Components({
      resolvers: [AntDesignVueResolver({ importStyle: false })],
      dts: 'src/components.d.ts',
    }),
  ],

  // Vite 配置：https://cn.vitejs.dev/config/
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },

  // Tauri 固定端口，若端口被占用直接失败
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
    host: host || false,
    hmr: host
      ? { protocol: 'ws', host, port: 5174 }
      : undefined,
    watch: { ignored: ['**/src-tauri/**'] },
  },

  // 环境变量前缀
  envPrefix: ['VITE_', 'TAURI_ENV_*'],
  build: {
    // Tauri WebView 性能考虑，禁用 sourcemap
    target: process.env.TAURI_ENV_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
    minify: !process.env.TAURI_ENV_DEBUG ? 'esbuild' : false,
    sourcemap: false,
  },
});
