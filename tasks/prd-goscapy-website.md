# PRD: goscapy 项目文档网站

## Introduction

为 goscapy 纯 Go 网络数据包库构建多页面文档网站。网站采用中英双语、顶部固定导航 + 侧边栏的经典文档站布局，风格参考 Goal Workflow 文档站（暖色系、卡片式、粒子动画、滚动触发动画）。目标是让用户能快速了解 goscapy 的能力、快速上手、查阅各协议场景的完整示例代码。

## Goals

- 提供结构清晰的多页面文档站（非单页），至少包含首页、快速开始、完整指南、4 个场景示例页
- 中英双语支持，每页可切换语言
- 风格参考 goal-workflow 文档站：暖色系、卡片布局、代码高亮、滚动动画、粒子背景
- 零依赖部署 — 纯静态 HTML/CSS/JS，本地可直接打开

## User Stories

### US-001: 网站框架与导航系统
**Description:** 作为网站访问者，我需要清晰的导航结构，以便在不同页面和语言之间自由切换。

**Acceptance Criteria:**
- [ ] 顶部固定导航栏，包含 Logo、页面链接（首页/快速开始/指南/示例）、语言切换按钮
- [ ] 侧边栏（示例页和指南页），显示当前页面的目录结构，支持滚动高亮
- [ ] 语言切换（中/英），点击后跳转到对应语言版本的同名页面
- [ ] 移动端响应式：侧边栏折叠为汉堡菜单
- [ ] 所有页面共享相同的导航框架（通过 JS 动态加载或构建时注入）
- [ ] 在浏览器中验证导航和语言切换正常工作

### US-002: 首页 (index.html)
**Description:** 作为潜在用户，我访问首页时能快速了解 goscapy 是什么、能做什么、如何安装。

**Acceptance Criteria:**
- [ ] Hero 区域：项目名称、一句话描述、GitHub star 数、Go Reference 链接
- [ ] 核心特性卡片（Builder API、Shortcut Functions、Packet Dissect、Send & Receive、Sniffing、Auto Checksums、Layer Binding、Cross-Platform）
- [ ] 支持的协议表格（链路层/网络层/传输层/隧道层/应用层/载荷层）
- [ ] 安装命令（`go get`）
- [ ] 快速代码示例（Ethernet + IP + ICMP 一行构建）
- [ ] Footer：许可证、GitHub 链接
- [ ] 滚动触发动画（参考 goal-workflow：粒子背景、卡片翻转、代码块滑入、section 淡入）
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有动画和内容正确渲染

### US-003: 快速开始页 (quickstart.html)
**Description:** 作为新用户，我希望能通过 5 分钟教程快速了解 goscapy 的核心用法。

**Acceptance Criteria:**
- [ ] 侧边栏目录：安装、构建数据包（Builder API）、构建数据包（Shortcut）、解析数据包、发送数据包、嗅探数据包
- [ ] 每个部分包含代码示例和简要说明
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 示例可直接复制运行
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有代码示例正确渲染

### US-004: 完整指南页 (guide.html)
**Description:** 作为开发者，我需要深入了解 goscapy 的架构、所有 Builder API、Shortcut 函数、协议注册机制、层间绑定等高级特性。

**Acceptance Criteria:**
- [ ] 侧边栏目录覆盖：包结构总览、Builder API 完整参考（所有 15 个 Builder 的参数和用法）、Shortcut 函数参考（所有 14 个 Shortcut）、层间绑定机制、协议注册系统（Key Field / Next-Layer / Heuristic / Tunnel）、自动校验和、构建钩子、解析器管线、发送与接收（L2/L3）、嗅探（回调和通道式）、BPF 过滤器、平台差异（Darwin/Linux）
- [ ] Builder API 部分以表格形式列出每个 Builder 的方法签名
- [ ] 关键概念配有 note/tip 提示框
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有内容正确渲染

### US-005: 示例页 — 基础组包
**Description:** 作为用户，我需要看到 Ethernet/IP/TCP/UDP/ICMP/ARP 的完整构建和解析示例。

**Acceptance Criteria:**
- [ ] 侧边栏目录：Ethernet + IP + ICMP Echo、Ethernet + IP + TCP SYN、Ethernet + IP + UDP、Ethernet + ARP、IP + ICMP（无 Ethernet）、IP + TCP、IP + UDP
- [ ] 每个示例包含：Builder API 构建代码、对应的 Shortcut 写法、解析代码、序列化后的十六进制字节展示
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 示例可一键复制
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有示例正确渲染

### US-006: 示例页 — 隧道封装
**Description:** 作为用户，我需要看到 GRE、VXLAN、Dot1Q (VLAN) 的隧道封装示例。

**Acceptance Criteria:**
- [ ] 侧边栏目录：GRE 隧道（Ethernet + IP + GRE + Inner IP）、VXLAN 隧道（Ethernet + IP + UDP + VXLAN + Inner Ethernet）、Dot1Q VLAN（Ethernet + Dot1Q + IP）、QinQ 双层 VLAN
- [ ] 每个示例包含：Builder API 代码、Shortcut 写法、解析代码
- [ ] 展示 GRE 的 Key/Seq/Checksum 条件字段用法
- [ ] 展示 VXLAN 的 VNI 设置
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有示例正确渲染

### US-007: 示例页 — 应用协议 (DNS/DHCP)
**Description:** 作为用户，我需要看到 DNS 查询和 DHCP 请求的完整示例。

**Acceptance Criteria:**
- [ ] 侧边栏目录：DNS 查询（A 记录）、DNS 响应解析、DHCP Discover、DHCP Offer
- [ ] DNS 示例展示 DNSQuestion 结构体用法
- [ ] DHCP 示例展示 MessageType 和各地址字段设置
- [ ] 展示 DNS 标签压缩的序列化结果
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有示例正确渲染

### US-008: 示例页 — IPv6/ICMPv6
**Description:** 作为用户，我需要看到 IPv6、ICMPv6 Echo、NDP 的完整示例。

**Acceptance Criteria:**
- [ ] 侧边栏目录：IPv6 + ICMPv6 Echo、IPv6 + TCP、IPv6 + UDP、ICMPv6 NDP Router Solicitation、ICMPv6 NDP Neighbor Advertisement、IPv6 扩展头链（Hop-by-Hop + Fragment + TCP）
- [ ] IPv6 示例展示 TC/FL/HLim 字段设置
- [ ] ICMPv6 示例展示 Echo ID/Seq 子层
- [ ] NDP 示例展示各 NDP 子类型
- [ ] 展示 IPv6 伪头部校验和的自动计算
- [ ] 代码块使用深色背景 + 语法高亮
- [ ] 中英双语版本均完整
- [ ] 在浏览器中验证所有示例正确渲染

## Functional Requirements

- FR-1: 网站必须包含 8 个页面类型（首页、快速开始、指南、4 个示例页），每种提供中英双语版本，共计 16 个 HTML 文件
- FR-2: 顶部导航栏必须固定在页面顶部，包含 Logo、导航链接、语言切换按钮
- FR-3: 侧边栏必须在指南页和示例页中显示，内容为当前页面的章节目录，支持滚动高亮当前章节
- FR-4: 语言切换必须通过顶部按钮触发，跳转到对应语言的同名页面
- FR-5: 代码块必须使用深色背景（`#1a1a1a`）和等宽字体（SF Mono / Fira Code），Go 代码关键字需语法高亮
- FR-6: 网站必须支持响应式布局，移动端侧边栏折叠为汉堡菜单
- FR-7: 所有页面必须共享统一的 CSS 样式（颜色、字体、间距、动画）
- FR-8: 滚动动画效果必须包含：section 淡入上移、代码块滑入、卡片翻转、表格行逐行淡入、note/tip 提示框滑入
- FR-9: 粒子背景动画必须在所有页面运行
- FR-10: 网站必须是纯静态 HTML/CSS/JS，无构建工具依赖，本地浏览器可直接打开
- FR-11: 示例代码必须是完整的、可运行的 Go 代码片段

## Non-Goals (Out of Scope)

- **不实现服务端渲染** — 纯静态页面，无需后端
- **不实现搜索功能** — 侧边栏目录和导航替代
- **不实现 API 文档自动生成** — 示例为手工编写，非 pkg.go.dev 替代
- **不实现暗色模式** — 仅暖色主题
- **不需要构建工具（webpack/vite 等）** — 纯 HTML/CSS/JS，直接在浏览器中打开
- **不需要 npm 依赖** — anime.js 和 Google Fonts 通过 CDN 加载

## Design Considerations

- **色彩系统**（来自 goal-workflow 风格）：
  - 主背景：`#FAF9F6`（暖白）
  - 卡片背景：`#FFFFFF`
  - 主文字：`#1a1a1a`
  - 次要文字：`#4A4540`
  - 辅助文字：`#8B8680` / `#B0AAA4`
  - 强调色：`#D97757`（terracotta，链接、按钮）
  - 成功色：`#5B8A72`（sage，tip 提示框）
  - 代码背景：`#1a1a1a`
  - 代码文字：`#E8E4DE`
  - 边框：`#E8E4DE`
  - 更多强调色：`#8B6F8A`（plum）、`#4A6FA5`（blue）、`#D4A843`（amber）、`#2D9CDB`（teal）、`#7C5CBF`（violet）
- **字体**：Inter（正文）、SF Mono / Fira Code / JetBrains Mono（代码）
- **动画**：anime.js CDN 加载，滚动触发（Intersection Observer）
- **粒子背景**：Canvas 实现，约 60 个彩色粒子，带连线效果

## Technical Considerations

- **目录结构**：
  ```
  docs/
  ├── index.html              # 首页（默认英文，或根据浏览器语言跳转）
  ├── zh/
  │   ├── index.html          # 中文首页
  │   ├── quickstart.html     # 中文快速开始
  │   ├── guide.html          # 中文完整指南
  │   └── examples/
  │       ├── basic.html      # 基础组包
  │       ├── tunnel.html     # 隧道封装
  │       ├── app.html        # 应用协议 (DNS/DHCP)
  │       └── ipv6.html       # IPv6/ICMPv6
  ├── en/
  │   ├── index.html
  │   ├── quickstart.html
  │   ├── guide.html
  │   └── examples/
  │       ├── basic.html
  │       ├── tunnel.html
  │       ├── app.html
  │       └── ipv6.html
  ├── css/
  │   └── style.css           # 共享样式
  └── js/
      ├── nav.js              # 导航栏动态加载
      ├── sidebar.js          # 侧边栏生成与高亮
      ├── particles.js        # 粒子背景
      └── animations.js       # 滚动动画
  ```
- **CSS 共享机制**：所有页面引用同一个 `css/style.css`，避免样式重复
- **导航栏加载**：通过 `js/nav.js` 动态注入导航栏 HTML，确保一致性
- **侧边栏生成**：通过 `js/sidebar.js` 扫描页面中的 `h2`/`h3` 标签自动生成目录，监听 scroll 事件高亮当前章节
- **语言切换**：顶部按钮维护当前路径映射，点击后跳转到对应语言版本
- **零依赖**：除 anime.js（CDN）和 Google Fonts（CDN）外无外部依赖，本地 `file://` 协议可直接打开所有页面

## File Creation Plan

```
docs/css/style.css             — 全局样式（颜色、字体、布局、卡片、表格、代码块、note/tip、badge、响应式）
docs/js/nav.js                 — 顶部导航栏动态注入 + 语言切换逻辑
docs/js/sidebar.js             — 侧边栏目录自动生成 + 滚动高亮
docs/js/particles.js           — Canvas 粒子背景动画
docs/js/animations.js          — 滚动触发动画（Intersection Observer + anime.js）

docs/index.html                — 入口页，检测浏览器语言跳转到 en/ 或 zh/
docs/en/index.html             — 英文首页
docs/en/quickstart.html        — 英文快速开始
docs/en/guide.html             — 英文完整指南
docs/en/examples/basic.html    — 英文基础组包示例
docs/en/examples/tunnel.html   — 英文隧道封装示例
docs/en/examples/app.html      — 英文应用协议示例
docs/en/examples/ipv6.html     — 英文 IPv6/ICMPv6 示例

docs/zh/index.html             — 中文首页
docs/zh/quickstart.html        — 中文快速开始
docs/zh/guide.html             — 中文完整指南
docs/zh/examples/basic.html    — 中文基础组包示例
docs/zh/examples/tunnel.html   — 中文隧道封装示例
docs/zh/examples/app.html      — 中文应用协议示例
docs/zh/examples/ipv6.html     — 中文 IPv6/ICMPv6 示例
```

## Success Metrics

- 16 个 HTML 文件创建完成，所有页面可正常访问
- 所有链接、导航、语言切换正常工作
- 中英双语内容准确对应
- 所有代码示例语法正确、可复制
- 在 Chrome/Safari/Firefox 中渲染一致
- 移动端响应式正常（侧边栏折叠、表格横向滚动）

## Open Questions

- 后续是否需要新增 LLDP/ERSPAN/OSPF/BGP/QUIC 的示例页？（建议等协议实现后追加）
- 是否需要自动部署到 GitHub Pages 的 CI？（当前先本地手动部署）