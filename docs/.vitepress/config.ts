import { defineConfig } from "vitepress";

export default defineConfig({
  title: "vigilant-heron",
  description:
    "A reverse-proxy router that screens web requests with typed decision models and blocks, redirects or forwards them",
  base: "/vigilant-heron/",

  themeConfig: {
    logo: "/logo.svg",

    nav: [
      { text: "Home", link: "/" },
      { text: "Getting Started", link: "/getting-started" },
      { text: "Install", link: "/install" },
      { text: "Rules", link: "/rules" },
      { text: "Changelog", link: "/changelog" },
    ],

    sidebar: [
      {
        text: "Guide",
        items: [
          { text: "Getting Started", link: "/getting-started" },
          { text: "Installation", link: "/install" },
          { text: "Command line", link: "/cli" },
          { text: "How it works", link: "/how-it-works" },
          { text: "Decision backends", link: "/decision-backends" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "Configuration", link: "/configuration" },
          { text: "Rules", link: "/rules" },
          { text: "Built-in rules", link: "/builtin-rules" },
          { text: "Limits", link: "/limits" },
          { text: "Logging", link: "/logging" },
          { text: "Timeouts and limits", link: "/timeouts" },
        ],
      },
      {
        text: "Support",
        items: [
          { text: "Troubleshooting", link: "/troubleshooting" },
          { text: "Security", link: "/security" },
          { text: "Evaluation", link: "/evaluation" },
          { text: "Contributing", link: "/contributing" },
          { text: "Changelog", link: "/changelog" },
        ],
      },
    ],

    socialLinks: [
      { icon: "github", link: "https://github.com/coo-quack/vigilant-heron" },
    ],

    footer: {
      message: "Released under the MIT License.",
      copyright: "Copyright © 2026 coo-quack",
    },

    search: {
      provider: "local",
    },
  },

  head: [
    [
      "link",
      {
        rel: "icon",
        type: "image/svg+xml",
        href: "/vigilant-heron/logo.svg",
      },
    ],
  ],
});
