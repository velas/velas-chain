module.exports = {
  title: "Velas Docs",
  tagline:
    "Velas is an open source project implementing a new, high-performance, permissionless blockchain.",
  url: "https://docs.next.velas.com",
  baseUrl: "/",
  favicon: "img/favicon.ico",
  organizationName: "velas", // Usually your GitHub org/user name.
  projectName: "velas", // Usually your repo name.
  themeConfig: {
    navbar: {
      logo: {
        alt: "Solana Logo",
        src: "img/logo-horizontal.svg",
        srcDark: "img/logo-horizontal-dark.svg",
      },
      links: [
        {
          to: "evm",
          label: "Evm integration",
          position: "left",
        },
        {
          to: "apps",
          label: "Develop",
          position: "left",
        },
        {
          to: "running-validator",
          label: "Validate",
          position: "left",
        },
        {
          to: "integrations/exchange",
          label: "Integrate",
          position: "left",
        },
        {
          to: "cluster/overview",
          label: "Learn",
          position: "left",
        },
        {
          href: "https://github.com/velas",
          label: "GitHub",
          position: "right",
        },
      ],
    },
    algolia: {
      // This API key is "search-only" and safe to be published
      apiKey: "d58e0d68c875346d52645d68b13f3ac0",
      indexName: "velas",
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            {
              label: "Introduction",
              to: "introduction",
            },
          ],
        },
        {
          title: "Community",
          items: [
            {
              label: "Telegram",
              href: "https://t.me/VelasDevelopers",
            },
          ],
        },
        {
          title: "More",
          items: [
            {
              label: "GitHub",
              href: "https://github.com/velas",
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Velas Foundation`,
    },
  },
  presets: [
    [
      "@docusaurus/preset-classic",
      {
        docs: {
          path: "src",
          routeBasePath: "/",
          sidebarPath: require.resolve("./sidebars.js"),
        },
        theme: {
          customCss: require.resolve("./src/css/custom.css"),
        },
      },
    ],
  ],
};
