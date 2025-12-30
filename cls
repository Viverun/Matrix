[33mcommit 080a520f82005442cd7e8e261515f4868560a0ae[m[33m ([m[1;36mHEAD[m[33m -> [m[1;32mmain[m[33m)[m
Author: Viverun <185501522+Viverun@users.noreply.github.com>
Date:   Mon Dec 29 02:52:34 2025 +0530

    Matrix v.0.1

 .gitignore                                         |   24 [32m+[m[31m-[m
 .../__pycache__/api_security_agent.cpython-312.pyc |  Bin [31m40729[m -> [32m47297[m bytes
 backend/agents/api_security_agent.py               |  143 [32m+[m[31m-[m
 backend/check_http.py                              |   18 [32m+[m
 backend/core/__pycache__/chatbot.cpython-312.pyc   |  Bin [31m12334[m -> [32m12587[m bytes
 backend/core/chatbot.py                            |   28 [32m+[m[31m-[m
 backend/matrix.db-wal                              |  Bin [31m4185952[m -> [32m4185952[m bytes
 frontend/.next/app-build-manifest.json             |   55 [31m-[m
 frontend/.next/build-manifest.json                 |   30 [31m-[m
 frontend/.next/cache/.tsbuildinfo                  |    1 [31m-[m
 ...FsJfOCGO8v6gtoFDqE+CFCbCAG-UL3HoA0EetoIf0=.webp |  Bin [31m6862[m -> [32m0[m bytes
 .../webpack/client-development-fallback/0.pack.gz  |  Bin [31m11832820[m -> [32m0[m bytes
 .../webpack/client-development-fallback/1.pack.gz  |  Bin [31m5349[m -> [32m0[m bytes
 .../client-development-fallback/index.pack.gz      |  Bin [31m37386[m -> [32m0[m bytes
 .../client-development-fallback/index.pack.gz.old  |  Bin [31m37386[m -> [32m0[m bytes
 .../cache/webpack/client-development/0.pack.gz     |  Bin [31m215727[m -> [32m0[m bytes
 .../cache/webpack/client-development/1.pack.gz     |  Bin [31m370382[m -> [32m0[m bytes
 .../cache/webpack/client-development/10.pack.gz    |  Bin [31m606317[m -> [32m0[m bytes
 .../cache/webpack/client-development/11.pack.gz    |  Bin [31m574098[m -> [32m0[m bytes
 .../cache/webpack/client-development/12.pack.gz    |  Bin [31m3745049[m -> [32m0[m bytes
 .../cache/webpack/client-development/13.pack.gz    |  Bin [31m102071[m -> [32m0[m bytes
 .../cache/webpack/client-development/14.pack.gz    |  Bin [31m552392[m -> [32m0[m bytes
 .../cache/webpack/client-development/15.pack.gz    |  Bin [31m156190[m -> [32m0[m bytes
 .../cache/webpack/client-development/16.pack.gz    |  Bin [31m916919[m -> [32m0[m bytes
 .../cache/webpack/client-development/17.pack.gz    |  Bin [31m10290[m -> [32m0[m bytes
 .../cache/webpack/client-development/18.pack.gz    |  Bin [31m2345[m -> [32m0[m bytes
 .../cache/webpack/client-development/19.pack.gz    |  Bin [31m7706163[m -> [32m0[m bytes
 .../cache/webpack/client-development/2.pack.gz     |  Bin [31m920946[m -> [32m0[m bytes
 .../cache/webpack/client-development/20.pack.gz    |  Bin [31m3069908[m -> [32m0[m bytes
 .../cache/webpack/client-development/21.pack.gz    |  Bin [31m5505[m -> [32m0[m bytes
 .../cache/webpack/client-development/22.pack.gz    |  Bin [31m9874492[m -> [32m0[m bytes
 .../cache/webpack/client-development/23.pack.gz    |  Bin [31m154123[m -> [32m0[m bytes
 .../cache/webpack/client-development/24.pack.gz    |  Bin [31m2208[m -> [32m0[m bytes
 .../cache/webpack/client-development/25.pack.gz    |  Bin [31m7400[m -> [32m0[m bytes
 .../cache/webpack/client-development/26.pack.gz    |  Bin [31m264507[m -> [32m0[m bytes
 .../cache/webpack/client-development/27.pack.gz    |  Bin [31m589667[m -> [32m0[m bytes
 .../cache/webpack/client-development/3.pack.gz     |  Bin [31m2031[m -> [32m0[m bytes
 .../cache/webpack/client-development/4.pack.gz     |  Bin [31m10688998[m -> [32m0[m bytes
 .../cache/webpack/client-development/5.pack.gz     |  Bin [31m2746111[m -> [32m0[m bytes
 .../cache/webpack/client-development/6.pack.gz     |  Bin [31m574263[m -> [32m0[m bytes
 .../cache/webpack/client-development/7.pack.gz     |  Bin [31m7698981[m -> [32m0[m bytes
 .../cache/webpack/client-development/8.pack.gz     |  Bin [31m263129[m -> [32m0[m bytes
 .../cache/webpack/client-development/9.pack.gz     |  Bin [31m214526[m -> [32m0[m bytes
 .../cache/webpack/client-development/index.pack.gz |  Bin [31m211312[m -> [32m0[m bytes
 .../webpack/client-development/index.pack.gz.old   |  Bin [31m211329[m -> [32m0[m bytes
 .../.next/cache/webpack/client-production/0.pack   |  Bin [31m19585408[m -> [32m0[m bytes
 .../cache/webpack/client-production/index.pack     |  Bin [31m2160419[m -> [32m0[m bytes
 .../cache/webpack/server-development/0.pack.gz     |  Bin [31m191998[m -> [32m0[m bytes
 .../cache/webpack/server-development/1.pack.gz     |  Bin [31m210708[m -> [32m0[m bytes
 .../cache/webpack/server-development/10.pack.gz    |  Bin [31m440958[m -> [32m0[m bytes
 .../cache/webpack/server-development/11.pack.gz    |  Bin [31m287944[m -> [32m0[m bytes
 .../cache/webpack/server-development/12.pack.gz    |  Bin [31m2582207[m -> [32m0[m bytes
 .../cache/webpack/server-development/13.pack.gz    |  Bin [31m2812907[m -> [32m0[m bytes
 .../cache/webpack/server-development/14.pack.gz    |  Bin [31m361403[m -> [32m0[m bytes
 .../cache/webpack/server-development/15.pack.gz    |  Bin [31m108275[m -> [32m0[m bytes
 .../cache/webpack/server-development/16.pack.gz    |  Bin [31m1645559[m -> [32m0[m bytes
 .../cache/webpack/server-development/17.pack.gz    |  Bin [31m3536546[m -> [32m0[m bytes
 .../cache/webpack/server-development/18.pack.gz    |  Bin [31m128553[m -> [32m0[m bytes
 .../cache/webpack/server-development/19.pack.gz    |  Bin [31m300690[m -> [32m0[m bytes
 .../cache/webpack/server-development/2.pack.gz     |  Bin [31m285081[m -> [32m0[m bytes
 .../cache/webpack/server-development/20.pack.gz    |  Bin [31m320491[m -> [32m0[m bytes
 .../cache/webpack/server-development/3.pack.gz     |  Bin [31m257391[m -> [32m0[m bytes
 .../cache/webpack/server-development/4.pack.gz     |  Bin [31m4601868[m -> [32m0[m bytes
 .../cache/webpack/server-development/5.pack.gz     |  Bin [31m6692[m -> [32m0[m bytes
 .../cache/webpack/server-development/6.pack.gz     |  Bin [31m442975[m -> [32m0[m bytes
 .../cache/webpack/server-development/7.pack.gz     |  Bin [31m3819567[m -> [32m0[m bytes
 .../cache/webpack/server-development/8.pack.gz     |  Bin [31m4389[m -> [32m0[m bytes
 .../cache/webpack/server-development/9.pack.gz     |  Bin [31m1645495[m -> [32m0[m bytes
 .../cache/webpack/server-development/index.pack.gz |  Bin [31m146958[m -> [32m0[m bytes
 .../webpack/server-development/index.pack.gz.old   |  Bin [31m146939[m -> [32m0[m bytes
 .../.next/cache/webpack/server-production/0.pack   |  Bin [31m14892166[m -> [32m0[m bytes
 .../cache/webpack/server-production/index.pack     |  Bin [31m1345923[m -> [32m0[m bytes
 frontend/.next/fallback-build-manifest.json        |   27 [31m-[m
 frontend/.next/package.json                        |    1 [31m-[m
 frontend/.next/react-loadable-manifest.json        |    1 [31m-[m
 frontend/.next/server/_error.js                    |   66 [31m-[m
 frontend/.next/server/app-paths-manifest.json      |    7 [31m-[m
 .../app/_not-found_client-reference-manifest.js    |    1 [31m-[m
 frontend/.next/server/app/analytics/page.js        |  290 [31m--[m
 .../analytics/page_client-reference-manifest.js    |    1 [31m-[m
 frontend/.next/server/app/dashboard/page.js        |  290 [31m--[m
 .../dashboard/page_client-reference-manifest.js    |    1 [31m-[m
 frontend/.next/server/app/hub/page.js              |  268 [31m--[m
 .../app/hub/page_client-reference-manifest.js      |    1 [31m-[m
 frontend/.next/server/app/login/page.js            |  257 [31m--[m
 .../app/login/page_client-reference-manifest.js    |    1 [31m-[m
 frontend/.next/server/app/not-found.js             |  196 [31m-[m
 .../app/not-found_client-reference-manifest.js     |    1 [31m-[m
 frontend/.next/server/app/page.js                  |  279 [31m--[m
 .../server/app/page_client-reference-manifest.js   |    1 [31m-[m
 frontend/.next/server/app/repo/page.js             |  355 [31m--[m
 .../app/repo/page_client-reference-manifest.js     |    1 [31m-[m
 frontend/.next/server/app/scan/page.js             |  290 [31m--[m
 .../app/scan/page_client-reference-manifest.js     |    1 [31m-[m
 frontend/.next/server/app/scans/[id]/page.js       |  290 [31m--[m
 .../scans/[id]/page_client-reference-manifest.js   |    1 [31m-[m
 frontend/.next/server/app/signup/page.js           |  257 [31m--[m
 .../app/signup/page_client-reference-manifest.js   |    1 [31m-[m
 frontend/.next/server/middleware-build-manifest.js |    1 [31m-[m
 frontend/.next/server/middleware-manifest.json     |    6 [31m-[m
 .../server/middleware-react-loadable-manifest.js   |    1 [31m-[m
 frontend/.next/server/next-font-manifest.js        |    1 [31m-[m
 frontend/.next/server/next-font-manifest.json      |    1 [31m-[m
 frontend/.next/server/pages-manifest.json          |    5 [31m-[m
 frontend/.next/server/pages/_app.js                |   36 [31m-[m
 frontend/.next/server/pages/_document.js           |   56 [31m-[m
 frontend/.next/server/pages/_error.js              |   66 [31m-[m
 frontend/.next/server/server-reference-manifest.js |    1 [31m-[m
 .../.next/server/server-reference-manifest.json    |    5 [31m-[m
 frontend/.next/server/vendor-chunks/@swc.js        |   95 [31m-[m
 .../.next/server/vendor-chunks/lucide-react.js     |  355 [31m--[m
 frontend/.next/server/vendor-chunks/next.js        | 2682 [31m-------------[m
 frontend/.next/server/webpack-runtime.js           |  215 [31m-[m
 ...s-browser_components_ScanPDFExportButton_tsx.js | 1623 [31m--------[m
 frontend/.next/static/chunks/_error.js             |   28 [31m-[m
 .../.next/static/chunks/app-pages-internals.js     |  116 [31m-[m
 frontend/.next/static/chunks/app/analytics/page.js |  565 [31m---[m
 frontend/.next/static/chunks/app/dashboard/page.js |  543 [31m---[m
 frontend/.next/static/chunks/app/hub/page.js       |  411 [31m--[m
 frontend/.next/static/chunks/app/layout.js         |   82 [31m-[m
 frontend/.next/static/chunks/app/login/page.js     |  422 [31m--[m
 frontend/.next/static/chunks/app/not-found.js      |   39 [31m-[m
 frontend/.next/static/chunks/app/page.js           |  433 [31m--[m
 frontend/.next/static/chunks/app/repo/page.js      | 3009 [31m--------------[m
 frontend/.next/static/chunks/app/scan/page.js      |  686 [31m----[m
 .../.next/static/chunks/app/scans/[id]/page.js     |  587 [31m---[m
 frontend/.next/static/chunks/app/signup/page.js    |  422 [31m--[m
 frontend/.next/static/chunks/fallback/amp.js       |  819 [31m----[m
 frontend/.next/static/chunks/fallback/main.js      | 1263 [31m------[m
 .../.next/static/chunks/fallback/pages/_app.js     |   28 [31m-[m
 .../.next/static/chunks/fallback/pages/_error.js   |   28 [31m-[m
 .../.next/static/chunks/fallback/react-refresh.js  |   62 [31m-[m
 frontend/.next/static/chunks/fallback/webpack.js   | 1219 [31m------[m
 frontend/.next/static/chunks/main-app.js           | 1804 [31m---------[m
 frontend/.next/static/chunks/main.js               | 1340 [31m-------[m
 frontend/.next/static/chunks/pages/_app.js         |   28 [31m-[m
 frontend/.next/static/chunks/pages/_error.js       |   28 [31m-[m
 frontend/.next/static/chunks/polyfills.js          |    1 [31m-[m
 frontend/.next/static/chunks/react-refresh.js      |   62 [31m-[m
 frontend/.next/static/chunks/webpack.js            | 1411 [31m-------[m
 frontend/.next/static/css/app/layout.css           | 4169 [31m--------------------[m
 .../.next/static/development/_buildManifest.js     |    1 [31m-[m
 frontend/.next/static/development/_ssgManifest.js  |    1 [31m-[m
 .../0344369fbf3c9c0c.webpack.hot-update.json       |    1 [31m-[m
 .../0561c3cca470047f.webpack.hot-update.json       |    1 [31m-[m
 .../0d7b11d370df8a4c.webpack.hot-update.json       |    1 [31m-[m
 .../1b1ba2ff2d604be4.webpack.hot-update.json       |    1 [31m-[m
 .../23688be8268414c4.webpack.hot-update.json       |    1 [31m-[m
 .../240d43b43fe08276.webpack.hot-update.json       |    1 [31m-[m
 .../3bd17ddd76e6a333.webpack.hot-update.json       |    1 [31m-[m
 .../4fb45b3b37a8141e.webpack.hot-update.json       |    1 [31m-[m
 .../57964a01892cd517.webpack.hot-update.json       |    1 [31m-[m
 .../5a34bc9790d15262.webpack.hot-update.json       |    1 [31m-[m
 .../5c595c84ca2caeec.webpack.hot-update.json       |    1 [31m-[m
 .../webpack/633457081244afec._.hot-update.json     |    1 [31m-[m
 .../7c41ab3c627613ba.webpack.hot-update.json       |    1 [31m-[m
 .../8e085c26b1151515.webpack.hot-update.json       |    1 [31m-[m
 .../952388a0ce5c873e.webpack.hot-update.json       |    1 [31m-[m
 .../a3e5a34a0ca8c284.webpack.hot-update.json       |    1 [31m-[m
 .../a5aa3bf69f19f57a.webpack.hot-update.json       |    1 [31m-[m
 .../a6792e20231312f4.webpack.hot-update.json       |    1 [31m-[m
 .../ace931312dd33aee.webpack.hot-update.json       |    1 [31m-[m
 .../ae17b31d4555812f.webpack.hot-update.json       |    1 [31m-[m
 .../ae7513d4eb42e74e.webpack.hot-update.json       |    1 [31m-[m
 .../app/layout.0344369fbf3c9c0c.hot-update.js      |   22 [31m-[m
 .../app/layout.0561c3cca470047f.hot-update.js      |   22 [31m-[m
 .../app/layout.0d7b11d370df8a4c.hot-update.js      |   22 [31m-[m
 .../app/layout.1b1ba2ff2d604be4.hot-update.js      |   22 [31m-[m
 .../app/layout.23688be8268414c4.hot-update.js      |   22 [31m-[m
 .../app/layout.240d43b43fe08276.hot-update.js      |   22 [31m-[m
 .../app/layout.3bd17ddd76e6a333.hot-update.js      |   22 [31m-[m
 .../app/layout.4fb45b3b37a8141e.hot-update.js      |   22 [31m-[m
 .../app/layout.57964a01892cd517.hot-update.js      |   22 [31m-[m
 .../app/layout.5a34bc9790d15262.hot-update.js      |   22 [31m-[m
 .../app/layout.5c595c84ca2caeec.hot-update.js      |   22 [31m-[m
 .../app/layout.7c41ab3c627613ba.hot-update.js      |   22 [31m-[m
 .../app/layout.8e085c26b1151515.hot-update.js      |   22 [31m-[m
 .../app/layout.952388a0ce5c873e.hot-update.js      |   22 [31m-[m
 .../app/layout.a3e5a34a0ca8c284.hot-update.js      |   22 [31m-[m
 .../app/layout.ace931312dd33aee.hot-update.js      |   22 [31m-[m
 .../app/layout.ae17b31d4555812f.hot-update.js      |   22 [31m-[m
 .../app/layout.ae7513d4eb42e74e.hot-update.js      |   22 [31m-[m
 .../app/layout.b85570187297cd9e.hot-update.js      |   22 [31m-[m
 .../app/layout.b8ac91979423e662.hot-update.js      |   22 [31m-[m
 .../app/layout.d3fa5d6389da15d3.hot-update.js      |   22 [31m-[m
 .../app/layout.e351cfa9c56ba2da.hot-update.js      |   22 [31m-[m
 .../app/layout.ed6a1ea5fcf4b5b6.hot-update.js      |   22 [31m-[m
 .../app/layout.eee8ca8d6bb04e0f.hot-update.js      |   22 [31m-[m
 .../app/layout.fcc4ec905b3f7045.hot-update.js      |   22 [31m-[m
 .../app/repo/page.0561c3cca470047f.hot-update.js   |   22 [31m-[m
 .../app/repo/page.240d43b43fe08276.hot-update.js   |   22 [31m-[m
 .../app/repo/page.4fb45b3b37a8141e.hot-update.js   |   21 [31m-[m
 .../app/repo/page.a3e5a34a0ca8c284.hot-update.js   |   22 [31m-[m
 .../app/repo/page.a5aa3bf69f19f57a.hot-update.js   |  717 [31m----[m
 .../app/repo/page.fcc4ec905b3f7045.hot-update.js   |   32 [31m-[m
 .../app/scan/page.ae17b31d4555812f.hot-update.js   |   22 [31m-[m
 .../b85570187297cd9e.webpack.hot-update.json       |    1 [31m-[m
 .../b8ac91979423e662.webpack.hot-update.json       |    1 [31m-[m
 .../d3fa5d6389da15d3.webpack.hot-update.json       |    1 [31m-[m
 .../db230111e1299626.webpack.hot-update.json       |    1 [31m-[m
 .../e351cfa9c56ba2da.webpack.hot-update.json       |    1 [31m-[m
 .../ed6a1ea5fcf4b5b6.webpack.hot-update.json       |    1 [31m-[m
 .../eee8ca8d6bb04e0f.webpack.hot-update.json       |    1 [31m-[m
 .../fcc4ec905b3f7045.webpack.hot-update.json       |    1 [31m-[m
 .../webpack/webpack.0344369fbf3c9c0c.hot-update.js |   18 [31m-[m
 .../webpack/webpack.0561c3cca470047f.hot-update.js |   18 [31m-[m
 .../webpack/webpack.0d7b11d370df8a4c.hot-update.js |   18 [31m-[m
 .../webpack/webpack.1b1ba2ff2d604be4.hot-update.js |   18 [31m-[m
 .../webpack/webpack.23688be8268414c4.hot-update.js |   18 [31m-[m
 .../webpack/webpack.240d43b43fe08276.hot-update.js |   18 [31m-[m
 .../webpack/webpack.3bd17ddd76e6a333.hot-update.js |   18 [31m-[m
 .../webpack/webpack.4fb45b3b37a8141e.hot-update.js |   18 [31m-[m
 .../webpack/webpack.57964a01892cd517.hot-update.js |   27 [31m-[m
 .../webpack/webpack.5a34bc9790d15262.hot-update.js |   18 [31m-[m
 .../webpack/webpack.5c595c84ca2caeec.hot-update.js |   18 [31m-[m
 .../webpack/webpack.7c41ab3c627613ba.hot-update.js |   18 [31m-[m
 .../webpack/webpack.8e085c26b1151515.hot-update.js |   18 [31m-[m
 .../webpack/webpack.952388a0ce5c873e.hot-update.js |   18 [31m-[m
 .../webpack/webpack.a3e5a34a0ca8c284.hot-update.js |   18 [31m-[m
 .../webpack/webpack.a5aa3bf69f19f57a.hot-update.js |   18 [31m-[m
 .../webpack/webpack.a6792e20231312f4.hot-update.js |   18 [31m-[m
 .../webpack/webpack.ace931312dd33aee.hot-update.js |   18 [31m-[m
 .../webpack/webpack.ae17b31d4555812f.hot-update.js |   18 [31m-[m
 .../webpack/webpack.ae7513d4eb42e74e.hot-update.js |   18 [31m-[m
 .../webpack/webpack.b85570187297cd9e.hot-update.js |   18 [31m-[m
 .../webpack/webpack.b8ac91979423e662.hot-update.js |   18 [31m-[m
 .../webpack/webpack.d3fa5d6389da15d3.hot-update.js |   18 [31m-[m
 .../webpack/webpack.db230111e1299626.hot-update.js |   18 [31m-[m
 .../webpack/webpack.e351cfa9c56ba2da.hot-update.js |   18 [31m-[m
 .../webpack/webpack.ed6a1ea5fcf4b5b6.hot-update.js |   18 [31m-[m
 .../webpack/webpack.eee8ca8d6bb04e0f.hot-update.js |   18 [31m-[m
 .../webpack/webpack.fcc4ec905b3f7045.hot-update.js |   18 [31m-[m
 frontend/.next/trace                               |   59 [31m-[m
 frontend/.next/types/app/analytics/page.ts         |   79 [31m-[m
 frontend/.next/types/app/dashboard/page.ts         |   79 [31m-[m
 frontend/.next/types/app/hub/page.ts               |   79 [31m-[m
 frontend/.next/types/app/layout.ts                 |   79 [31m-[m
 frontend/.next/types/app/login/page.ts             |   79 [31m-[m
 frontend/.next/types/app/page.ts                   |   79 [31m-[m
 frontend/.next/types/app/repo/page.ts              |   79 [31m-[m
 frontend/.next/types/app/scan/page.ts              |   79 [31m-[m
 frontend/.next/types/app/scans/[id]/page.ts        |   79 [31m-[m
 frontend/.next/types/app/signup/page.ts            |   79 [31m-[m
 frontend/.next/types/package.json                  |    1 [31m-[m
 frontend/app/repo/page.tsx                         |    2 [32m+[m[31m-[m
 frontend/app/scan/page.tsx                         |   63 [32m+[m[31m-[m
 frontend/app/scans/[id]/page.tsx                   |   39 [32m+[m[31m-[m
 247 files changed, 270 insertions(+), 30574 deletions(-)

[33mcommit 796fad330cf3b7a6a207b40996fe136283d5e52b[m
Author: Viverun <185501522+Viverun@users.noreply.github.com>
Date:   Mon Dec 29 01:24:36 2025 +0530

    Remove Python virtual environment from repository

 .../Include/site/python3.12/greenlet/greenlet.h    |    164 [31m-[m
 .../google_auth_httplib2.cpython-312.pyc           |    Bin [31m11320[m -> [32m0[m bytes
 .../site-packages/__pycache__/py.cpython-312.pyc   |    Bin [31m480[m -> [32m0[m bytes
 .../site-packages/__pycache__/six.cpython-312.pyc  |    Bin [31m41328[m -> [32m0[m bytes
 .../__pycache__/typing_extensions.cpython-312.pyc  |    Bin [31m163628[m -> [32m0[m bytes
 .../_argon2_cffi_bindings/__init__.py              |      6 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m272[m -> [32m0[m bytes
 .../__pycache__/_ffi_build.cpython-312.pyc         |    Bin [31m6875[m -> [32m0[m bytes
 .../site-packages/_argon2_cffi_bindings/_ffi.pyd   |    Bin [31m60928[m -> [32m0[m bytes
 .../_argon2_cffi_bindings/_ffi_build.py            |    233 [31m-[m
 .../_cffi_backend.cp312-win_amd64.pyd              |    Bin [31m181248[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/_pytest/__init__.py |     13 [31m-[m
 .../_pytest/__pycache__/__init__.cpython-312.pyc   |    Bin [31m468[m -> [32m0[m bytes
 .../__pycache__/_argcomplete.cpython-312.pyc       |    Bin [31m4813[m -> [32m0[m bytes
 .../_pytest/__pycache__/_version.cpython-312.pyc   |    Bin [31m777[m -> [32m0[m bytes
 .../__pycache__/cacheprovider.cpython-312.pyc      |    Bin [31m31607[m -> [32m0[m bytes
 .../_pytest/__pycache__/capture.cpython-312.pyc    |    Bin [31m55682[m -> [32m0[m bytes
 .../_pytest/__pycache__/compat.cpython-312.pyc     |    Bin [31m13009[m -> [32m0[m bytes
 .../_pytest/__pycache__/debugging.cpython-312.pyc  |    Bin [31m18266[m -> [32m0[m bytes
 .../_pytest/__pycache__/deprecated.cpython-312.pyc |    Bin [31m3017[m -> [32m0[m bytes
 .../_pytest/__pycache__/doctest.cpython-312.pyc    |    Bin [31m32613[m -> [32m0[m bytes
 .../__pycache__/faulthandler.cpython-312.pyc       |    Bin [31m5067[m -> [32m0[m bytes
 .../_pytest/__pycache__/fixtures.cpython-312.pyc   |    Bin [31m82713[m -> [32m0[m bytes
 .../__pycache__/freeze_support.cpython-312.pyc     |    Bin [31m1812[m -> [32m0[m bytes
 .../_pytest/__pycache__/helpconfig.cpython-312.pyc |    Bin [31m13099[m -> [32m0[m bytes
 .../_pytest/__pycache__/hookspec.cpython-312.pyc   |    Bin [31m45754[m -> [32m0[m bytes
 .../_pytest/__pycache__/junitxml.cpython-312.pyc   |    Bin [31m33281[m -> [32m0[m bytes
 .../_pytest/__pycache__/legacypath.cpython-312.pyc |    Bin [31m24157[m -> [32m0[m bytes
 .../_pytest/__pycache__/logging.cpython-312.pyc    |    Bin [31m45814[m -> [32m0[m bytes
 .../_pytest/__pycache__/main.cpython-312.pyc       |    Bin [31m47270[m -> [32m0[m bytes
 .../__pycache__/monkeypatch.cpython-312.pyc        |    Bin [31m17183[m -> [32m0[m bytes
 .../_pytest/__pycache__/nodes.cpython-312.pyc      |    Bin [31m30815[m -> [32m0[m bytes
 .../_pytest/__pycache__/outcomes.cpython-312.pyc   |    Bin [31m11698[m -> [32m0[m bytes
 .../_pytest/__pycache__/pastebin.cpython-312.pyc   |    Bin [31m5855[m -> [32m0[m bytes
 .../_pytest/__pycache__/pathlib.cpython-312.pyc    |    Bin [31m41689[m -> [32m0[m bytes
 .../_pytest/__pycache__/pytester.cpython-312.pyc   |    Bin [31m84906[m -> [32m0[m bytes
 .../pytester_assertions.cpython-312.pyc            |    Bin [31m2477[m -> [32m0[m bytes
 .../_pytest/__pycache__/python.cpython-312.pyc     |    Bin [31m75128[m -> [32m0[m bytes
 .../_pytest/__pycache__/python_api.cpython-312.pyc |    Bin [31m35337[m -> [32m0[m bytes
 .../_pytest/__pycache__/raises.cpython-312.pyc     |    Bin [31m59982[m -> [32m0[m bytes
 .../_pytest/__pycache__/recwarn.cpython-312.pyc    |    Bin [31m16045[m -> [32m0[m bytes
 .../_pytest/__pycache__/reports.cpython-312.pyc    |    Bin [31m26967[m -> [32m0[m bytes
 .../_pytest/__pycache__/runner.cpython-312.pyc     |    Bin [31m24167[m -> [32m0[m bytes
 .../_pytest/__pycache__/scope.cpython-312.pyc      |    Bin [31m3569[m -> [32m0[m bytes
 .../_pytest/__pycache__/setuponly.cpython-312.pyc  |    Bin [31m5351[m -> [32m0[m bytes
 .../_pytest/__pycache__/setupplan.cpython-312.pyc  |    Bin [31m1893[m -> [32m0[m bytes
 .../_pytest/__pycache__/skipping.cpython-312.pyc   |    Bin [31m14025[m -> [32m0[m bytes
 .../_pytest/__pycache__/stash.cpython-312.pyc      |    Bin [31m4356[m -> [32m0[m bytes
 .../_pytest/__pycache__/stepwise.cpython-312.pyc   |    Bin [31m9605[m -> [32m0[m bytes
 .../_pytest/__pycache__/subtests.cpython-312.pyc   |    Bin [31m17701[m -> [32m0[m bytes
 .../_pytest/__pycache__/terminal.cpython-312.pyc   |    Bin [31m84167[m -> [32m0[m bytes
 .../__pycache__/terminalprogress.cpython-312.pyc   |    Bin [31m1129[m -> [32m0[m bytes
 .../__pycache__/threadexception.cpython-312.pyc    |    Bin [31m5741[m -> [32m0[m bytes
 .../_pytest/__pycache__/timing.cpython-312.pyc     |    Bin [31m4771[m -> [32m0[m bytes
 .../_pytest/__pycache__/tmpdir.cpython-312.pyc     |    Bin [31m12744[m -> [32m0[m bytes
 .../__pycache__/tracemalloc.cpython-312.pyc        |    Bin [31m974[m -> [32m0[m bytes
 .../_pytest/__pycache__/unittest.cpython-312.pyc   |    Bin [31m26453[m -> [32m0[m bytes
 .../unraisableexception.cpython-312.pyc            |    Bin [31m6237[m -> [32m0[m bytes
 .../__pycache__/warning_types.cpython-312.pyc      |    Bin [31m6929[m -> [32m0[m bytes
 .../_pytest/__pycache__/warnings.cpython-312.pyc   |    Bin [31m6771[m -> [32m0[m bytes
 .../venv/Lib/site-packages/_pytest/_argcomplete.py |    117 [31m-[m
 .../Lib/site-packages/_pytest/_code/__init__.py    |     26 [31m-[m
 .../_code/__pycache__/__init__.cpython-312.pyc     |    Bin [31m674[m -> [32m0[m bytes
 .../_pytest/_code/__pycache__/code.cpython-312.pyc |    Bin [31m67874[m -> [32m0[m bytes
 .../_code/__pycache__/source.cpython-312.pyc       |    Bin [31m11918[m -> [32m0[m bytes
 .../venv/Lib/site-packages/_pytest/_code/code.py   |   1565 [31m-[m
 .../venv/Lib/site-packages/_pytest/_code/source.py |    225 [31m-[m
 .../venv/Lib/site-packages/_pytest/_io/__init__.py |     10 [31m-[m
 .../_io/__pycache__/__init__.cpython-312.pyc       |    Bin [31m365[m -> [32m0[m bytes
 .../_pytest/_io/__pycache__/pprint.cpython-312.pyc |    Bin [31m24375[m -> [32m0[m bytes
 .../_io/__pycache__/saferepr.cpython-312.pyc       |    Bin [31m5811[m -> [32m0[m bytes
 .../_io/__pycache__/terminalwriter.cpython-312.pyc |    Bin [31m11227[m -> [32m0[m bytes
 .../_io/__pycache__/wcwidth.cpython-312.pyc        |    Bin [31m1671[m -> [32m0[m bytes
 .../venv/Lib/site-packages/_pytest/_io/pprint.py   |    673 [31m-[m
 .../venv/Lib/site-packages/_pytest/_io/saferepr.py |    130 [31m-[m
 .../site-packages/_pytest/_io/terminalwriter.py    |    258 [31m-[m
 .../venv/Lib/site-packages/_pytest/_io/wcwidth.py  |     57 [31m-[m
 .../venv/Lib/site-packages/_pytest/_py/__init__.py |      0
 .../_py/__pycache__/__init__.cpython-312.pyc       |    Bin [31m173[m -> [32m0[m bytes
 .../_pytest/_py/__pycache__/error.cpython-312.pyc  |    Bin [31m4941[m -> [32m0[m bytes
 .../_pytest/_py/__pycache__/path.cpython-312.pyc   |    Bin [31m68700[m -> [32m0[m bytes
 .../venv/Lib/site-packages/_pytest/_py/error.py    |    119 [31m-[m
 backend/venv/Lib/site-packages/_pytest/_py/path.py |   1475 [31m-[m
 backend/venv/Lib/site-packages/_pytest/_version.py |     34 [31m-[m
 .../site-packages/_pytest/assertion/__init__.py    |    208 [31m-[m
 .../assertion/__pycache__/__init__.cpython-312.pyc |    Bin [31m10094[m -> [32m0[m bytes
 .../assertion/__pycache__/rewrite.cpython-312.pyc  |    Bin [31m61157[m -> [32m0[m bytes
 .../assertion/__pycache__/truncate.cpython-312.pyc |    Bin [31m4177[m -> [32m0[m bytes
 .../assertion/__pycache__/util.cpython-312.pyc     |    Bin [31m23807[m -> [32m0[m bytes
 .../Lib/site-packages/_pytest/assertion/rewrite.py |   1202 [31m-[m
 .../site-packages/_pytest/assertion/truncate.py    |    137 [31m-[m
 .../Lib/site-packages/_pytest/assertion/util.py    |    615 [31m-[m
 .../Lib/site-packages/_pytest/cacheprovider.py     |    646 [31m-[m
 backend/venv/Lib/site-packages/_pytest/capture.py  |   1144 [31m-[m
 backend/venv/Lib/site-packages/_pytest/compat.py   |    314 [31m-[m
 .../Lib/site-packages/_pytest/config/__init__.py   |   2197 [31m-[m
 .../config/__pycache__/__init__.cpython-312.pyc    |    Bin [31m91725[m -> [32m0[m bytes
 .../config/__pycache__/argparsing.cpython-312.pyc  |    Bin [31m26336[m -> [32m0[m bytes
 .../config/__pycache__/compat.cpython-312.pyc      |    Bin [31m3571[m -> [32m0[m bytes
 .../config/__pycache__/exceptions.cpython-312.pyc  |    Bin [31m801[m -> [32m0[m bytes
 .../config/__pycache__/findpaths.cpython-312.pyc   |    Bin [31m13242[m -> [32m0[m bytes
 .../Lib/site-packages/_pytest/config/argparsing.py |    578 [31m-[m
 .../Lib/site-packages/_pytest/config/compat.py     |     85 [31m-[m
 .../Lib/site-packages/_pytest/config/exceptions.py |     15 [31m-[m
 .../Lib/site-packages/_pytest/config/findpaths.py  |    350 [31m-[m
 .../venv/Lib/site-packages/_pytest/debugging.py    |    407 [31m-[m
 .../venv/Lib/site-packages/_pytest/deprecated.py   |     99 [31m-[m
 backend/venv/Lib/site-packages/_pytest/doctest.py  |    736 [31m-[m
 .../venv/Lib/site-packages/_pytest/faulthandler.py |    119 [31m-[m
 backend/venv/Lib/site-packages/_pytest/fixtures.py |   2047 [31m-[m
 .../Lib/site-packages/_pytest/freeze_support.py    |     45 [31m-[m
 .../venv/Lib/site-packages/_pytest/helpconfig.py   |    293 [31m-[m
 backend/venv/Lib/site-packages/_pytest/hookspec.py |   1342 [31m-[m
 backend/venv/Lib/site-packages/_pytest/junitxml.py |    695 [31m-[m
 .../venv/Lib/site-packages/_pytest/legacypath.py   |    468 [31m-[m
 backend/venv/Lib/site-packages/_pytest/logging.py  |    960 [31m-[m
 backend/venv/Lib/site-packages/_pytest/main.py     |   1203 [31m-[m
 .../Lib/site-packages/_pytest/mark/__init__.py     |    301 [31m-[m
 .../mark/__pycache__/__init__.cpython-312.pyc      |    Bin [31m13037[m -> [32m0[m bytes
 .../mark/__pycache__/expression.cpython-312.pyc    |    Bin [31m17350[m -> [32m0[m bytes
 .../mark/__pycache__/structures.cpython-312.pyc    |    Bin [31m27471[m -> [32m0[m bytes
 .../Lib/site-packages/_pytest/mark/expression.py   |    353 [31m-[m
 .../Lib/site-packages/_pytest/mark/structures.py   |    664 [31m-[m
 .../venv/Lib/site-packages/_pytest/monkeypatch.py  |    435 [31m-[m
 backend/venv/Lib/site-packages/_pytest/nodes.py    |    772 [31m-[m
 backend/venv/Lib/site-packages/_pytest/outcomes.py |    308 [31m-[m
 backend/venv/Lib/site-packages/_pytest/pastebin.py |    117 [31m-[m
 backend/venv/Lib/site-packages/_pytest/pathlib.py  |   1063 [31m-[m
 backend/venv/Lib/site-packages/_pytest/py.typed    |      0
 backend/venv/Lib/site-packages/_pytest/pytester.py |   1791 [31m-[m
 .../site-packages/_pytest/pytester_assertions.py   |     74 [31m-[m
 backend/venv/Lib/site-packages/_pytest/python.py   |   1772 [31m-[m
 .../venv/Lib/site-packages/_pytest/python_api.py   |    820 [31m-[m
 backend/venv/Lib/site-packages/_pytest/raises.py   |   1517 [31m-[m
 backend/venv/Lib/site-packages/_pytest/recwarn.py  |    367 [31m-[m
 backend/venv/Lib/site-packages/_pytest/reports.py  |    694 [31m-[m
 backend/venv/Lib/site-packages/_pytest/runner.py   |    580 [31m-[m
 backend/venv/Lib/site-packages/_pytest/scope.py    |     91 [31m-[m
 .../venv/Lib/site-packages/_pytest/setuponly.py    |     98 [31m-[m
 .../venv/Lib/site-packages/_pytest/setupplan.py    |     39 [31m-[m
 backend/venv/Lib/site-packages/_pytest/skipping.py |    321 [31m-[m
 backend/venv/Lib/site-packages/_pytest/stash.py    |    116 [31m-[m
 backend/venv/Lib/site-packages/_pytest/stepwise.py |    209 [31m-[m
 backend/venv/Lib/site-packages/_pytest/subtests.py |    411 [31m-[m
 backend/venv/Lib/site-packages/_pytest/terminal.py |   1763 [31m-[m
 .../Lib/site-packages/_pytest/terminalprogress.py  |     30 [31m-[m
 .../Lib/site-packages/_pytest/threadexception.py   |    152 [31m-[m
 backend/venv/Lib/site-packages/_pytest/timing.py   |     95 [31m-[m
 backend/venv/Lib/site-packages/_pytest/tmpdir.py   |    315 [31m-[m
 .../venv/Lib/site-packages/_pytest/tracemalloc.py  |     24 [31m-[m
 backend/venv/Lib/site-packages/_pytest/unittest.py |    628 [31m-[m
 .../site-packages/_pytest/unraisableexception.py   |    163 [31m-[m
 .../Lib/site-packages/_pytest/warning_types.py     |    172 [31m-[m
 backend/venv/Lib/site-packages/_pytest/warnings.py |    151 [31m-[m
 backend/venv/Lib/site-packages/_yaml/__init__.py   |     33 [31m-[m
 .../_yaml/__pycache__/__init__.cpython-312.pyc     |    Bin [31m849[m -> [32m0[m bytes
 .../aiohappyeyeballs-2.6.1.dist-info/INSTALLER     |      1 [31m-[m
 .../aiohappyeyeballs-2.6.1.dist-info/LICENSE       |    279 [31m-[m
 .../aiohappyeyeballs-2.6.1.dist-info/METADATA      |    123 [31m-[m
 .../aiohappyeyeballs-2.6.1.dist-info/RECORD        |     16 [31m-[m
 .../aiohappyeyeballs-2.6.1.dist-info/WHEEL         |      4 [31m-[m
 .../Lib/site-packages/aiohappyeyeballs/__init__.py |     14 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m494[m -> [32m0[m bytes
 .../__pycache__/_staggered.cpython-312.pyc         |    Bin [31m7939[m -> [32m0[m bytes
 .../__pycache__/impl.cpython-312.pyc               |    Bin [31m10061[m -> [32m0[m bytes
 .../__pycache__/types.cpython-312.pyc              |    Bin [31m590[m -> [32m0[m bytes
 .../__pycache__/utils.cpython-312.pyc              |    Bin [31m3672[m -> [32m0[m bytes
 .../site-packages/aiohappyeyeballs/_staggered.py   |    207 [31m-[m
 .../Lib/site-packages/aiohappyeyeballs/impl.py     |    259 [31m-[m
 .../Lib/site-packages/aiohappyeyeballs/py.typed    |      0
 .../Lib/site-packages/aiohappyeyeballs/types.py    |     17 [31m-[m
 .../Lib/site-packages/aiohappyeyeballs/utils.py    |     97 [31m-[m
 .../aiohttp-3.13.2.dist-info/INSTALLER             |      1 [31m-[m
 .../aiohttp-3.13.2.dist-info/METADATA              |    262 [31m-[m
 .../site-packages/aiohttp-3.13.2.dist-info/RECORD  |    139 [31m-[m
 .../aiohttp-3.13.2.dist-info/REQUESTED             |      0
 .../site-packages/aiohttp-3.13.2.dist-info/WHEEL   |      5 [31m-[m
 .../aiohttp-3.13.2.dist-info/licenses/LICENSE.txt  |     13 [31m-[m
 .../licenses/vendor/llhttp/LICENSE                 |     22 [31m-[m
 .../aiohttp-3.13.2.dist-info/top_level.txt         |      1 [31m-[m
 .../site-packages/aiohttp/.hash/_cparser.pxd.hash  |      1 [31m-[m
 .../aiohttp/.hash/_find_header.pxd.hash            |      1 [31m-[m
 .../aiohttp/.hash/_http_parser.pyx.hash            |      1 [31m-[m
 .../aiohttp/.hash/_http_writer.pyx.hash            |      1 [31m-[m
 .../Lib/site-packages/aiohttp/.hash/hdrs.py.hash   |      1 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/__init__.py |    278 [31m-[m
 .../aiohttp/__pycache__/__init__.cpython-312.pyc   |    Bin [31m5305[m -> [32m0[m bytes
 .../__pycache__/_cookie_helpers.cpython-312.pyc    |    Bin [31m10821[m -> [32m0[m bytes
 .../aiohttp/__pycache__/abc.cpython-312.pyc        |    Bin [31m12469[m -> [32m0[m bytes
 .../__pycache__/base_protocol.cpython-312.pyc      |    Bin [31m4512[m -> [32m0[m bytes
 .../aiohttp/__pycache__/client.cpython-312.pyc     |    Bin [31m56338[m -> [32m0[m bytes
 .../__pycache__/client_exceptions.cpython-312.pyc  |    Bin [31m17965[m -> [32m0[m bytes
 .../client_middleware_digest_auth.cpython-312.pyc  |    Bin [31m16268[m -> [32m0[m bytes
 .../__pycache__/client_middlewares.cpython-312.pyc |    Bin [31m2258[m -> [32m0[m bytes
 .../__pycache__/client_proto.cpython-312.pyc       |    Bin [31m13358[m -> [32m0[m bytes
 .../__pycache__/client_reqrep.cpython-312.pyc      |    Bin [31m64482[m -> [32m0[m bytes
 .../aiohttp/__pycache__/client_ws.cpython-312.pyc  |    Bin [31m22471[m -> [32m0[m bytes
 .../__pycache__/compression_utils.cpython-312.pyc  |    Bin [31m16842[m -> [32m0[m bytes
 .../aiohttp/__pycache__/connector.cpython-312.pyc  |    Bin [31m76448[m -> [32m0[m bytes
 .../aiohttp/__pycache__/cookiejar.cpython-312.pyc  |    Bin [31m21389[m -> [32m0[m bytes
 .../aiohttp/__pycache__/formdata.cpython-312.pyc   |    Bin [31m7597[m -> [32m0[m bytes
 .../aiohttp/__pycache__/hdrs.cpython-312.pyc       |    Bin [31m8471[m -> [32m0[m bytes
 .../aiohttp/__pycache__/helpers.cpython-312.pyc    |    Bin [31m43132[m -> [32m0[m bytes
 .../aiohttp/__pycache__/http.cpython-312.pyc       |    Bin [31m1677[m -> [32m0[m bytes
 .../__pycache__/http_exceptions.cpython-312.pyc    |    Bin [31m6141[m -> [32m0[m bytes
 .../__pycache__/http_parser.cpython-312.pyc        |    Bin [31m36559[m -> [32m0[m bytes
 .../__pycache__/http_websocket.cpython-312.pyc     |    Bin [31m960[m -> [32m0[m bytes
 .../__pycache__/http_writer.cpython-312.pyc        |    Bin [31m14518[m -> [32m0[m bytes
 .../aiohttp/__pycache__/log.cpython-312.pyc        |    Bin [31m709[m -> [32m0[m bytes
 .../aiohttp/__pycache__/multipart.cpython-312.pyc  |    Bin [31m52701[m -> [32m0[m bytes
 .../aiohttp/__pycache__/payload.cpython-312.pyc    |    Bin [31m48810[m -> [32m0[m bytes
 .../__pycache__/payload_streamer.cpython-312.pyc   |    Bin [31m4397[m -> [32m0[m bytes
 .../__pycache__/pytest_plugin.cpython-312.pyc      |    Bin [31m18440[m -> [32m0[m bytes
 .../aiohttp/__pycache__/resolver.cpython-312.pyc   |    Bin [31m10904[m -> [32m0[m bytes
 .../aiohttp/__pycache__/streams.cpython-312.pyc    |    Bin [31m31284[m -> [32m0[m bytes
 .../__pycache__/tcp_helpers.cpython-312.pyc        |    Bin [31m1755[m -> [32m0[m bytes
 .../aiohttp/__pycache__/test_utils.cpython-312.pyc |    Bin [31m34793[m -> [32m0[m bytes
 .../aiohttp/__pycache__/tracing.cpython-312.pyc    |    Bin [31m21888[m -> [32m0[m bytes
 .../aiohttp/__pycache__/typedefs.cpython-312.pyc   |    Bin [31m2261[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web.cpython-312.pyc        |    Bin [31m16122[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web_app.cpython-312.pyc    |    Bin [31m27200[m -> [32m0[m bytes
 .../__pycache__/web_exceptions.cpython-312.pyc     |    Bin [31m14993[m -> [32m0[m bytes
 .../__pycache__/web_fileresponse.cpython-312.pyc   |    Bin [31m17170[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web_log.cpython-312.pyc    |    Bin [31m10659[m -> [32m0[m bytes
 .../__pycache__/web_middlewares.cpython-312.pyc    |    Bin [31m5610[m -> [32m0[m bytes
 .../__pycache__/web_protocol.cpython-312.pyc       |    Bin [31m31216[m -> [32m0[m bytes
 .../__pycache__/web_request.cpython-312.pyc        |    Bin [31m38562[m -> [32m0[m bytes
 .../__pycache__/web_response.cpython-312.pyc       |    Bin [31m39135[m -> [32m0[m bytes
 .../__pycache__/web_routedef.cpython-312.pyc       |    Bin [31m11878[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web_runner.cpython-312.pyc |    Bin [31m19013[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web_server.cpython-312.pyc |    Bin [31m4892[m -> [32m0[m bytes
 .../__pycache__/web_urldispatcher.cpython-312.pyc  |    Bin [31m68626[m -> [32m0[m bytes
 .../aiohttp/__pycache__/web_ws.cpython-312.pyc     |    Bin [31m31533[m -> [32m0[m bytes
 .../aiohttp/__pycache__/worker.cpython-312.pyc     |    Bin [31m12052[m -> [32m0[m bytes
 .../Lib/site-packages/aiohttp/_cookie_helpers.py   |    334 [31m-[m
 .../venv/Lib/site-packages/aiohttp/_cparser.pxd    |    158 [31m-[m
 .../Lib/site-packages/aiohttp/_find_header.pxd     |      2 [31m-[m
 .../venv/Lib/site-packages/aiohttp/_headers.pxi    |     83 [31m-[m
 .../aiohttp/_http_parser.cp312-win_amd64.pyd       |    Bin [31m248832[m -> [32m0[m bytes
 .../Lib/site-packages/aiohttp/_http_parser.pyx     |    835 [31m-[m
 .../aiohttp/_http_writer.cp312-win_amd64.pyd       |    Bin [31m47104[m -> [32m0[m bytes
 .../Lib/site-packages/aiohttp/_http_writer.pyx     |    162 [31m-[m
 .../aiohttp/_websocket/.hash/mask.pxd.hash         |      1 [31m-[m
 .../aiohttp/_websocket/.hash/mask.pyx.hash         |      1 [31m-[m
 .../aiohttp/_websocket/.hash/reader_c.pxd.hash     |      1 [31m-[m
 .../site-packages/aiohttp/_websocket/__init__.py   |      1 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m232[m -> [32m0[m bytes
 .../_websocket/__pycache__/helpers.cpython-312.pyc |    Bin [31m5978[m -> [32m0[m bytes
 .../_websocket/__pycache__/models.cpython-312.pyc  |    Bin [31m3442[m -> [32m0[m bytes
 .../_websocket/__pycache__/reader.cpython-312.pyc  |    Bin [31m728[m -> [32m0[m bytes
 .../__pycache__/reader_c.cpython-312.pyc           |    Bin [31m17581[m -> [32m0[m bytes
 .../__pycache__/reader_py.cpython-312.pyc          |    Bin [31m17582[m -> [32m0[m bytes
 .../_websocket/__pycache__/writer.cpython-312.pyc  |    Bin [31m10302[m -> [32m0[m bytes
 .../site-packages/aiohttp/_websocket/helpers.py    |    147 [31m-[m
 .../aiohttp/_websocket/mask.cp312-win_amd64.pyd    |    Bin [31m36864[m -> [32m0[m bytes
 .../Lib/site-packages/aiohttp/_websocket/mask.pxd  |      3 [31m-[m
 .../Lib/site-packages/aiohttp/_websocket/mask.pyx  |     48 [31m-[m
 .../Lib/site-packages/aiohttp/_websocket/models.py |     84 [31m-[m
 .../Lib/site-packages/aiohttp/_websocket/reader.py |     31 [31m-[m
 .../_websocket/reader_c.cp312-win_amd64.pyd        |    Bin [31m147456[m -> [32m0[m bytes
 .../site-packages/aiohttp/_websocket/reader_c.pxd  |    110 [31m-[m
 .../site-packages/aiohttp/_websocket/reader_c.py   |    476 [31m-[m
 .../site-packages/aiohttp/_websocket/reader_py.py  |    476 [31m-[m
 .../Lib/site-packages/aiohttp/_websocket/writer.py |    262 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/abc.py      |    268 [31m-[m
 .../Lib/site-packages/aiohttp/base_protocol.py     |    100 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/client.py   |   1635 [31m-[m
 .../Lib/site-packages/aiohttp/client_exceptions.py |    421 [31m-[m
 .../aiohttp/client_middleware_digest_auth.py       |    476 [31m-[m
 .../site-packages/aiohttp/client_middlewares.py    |     55 [31m-[m
 .../venv/Lib/site-packages/aiohttp/client_proto.py |    359 [31m-[m
 .../Lib/site-packages/aiohttp/client_reqrep.py     |   1536 [31m-[m
 .../venv/Lib/site-packages/aiohttp/client_ws.py    |    428 [31m-[m
 .../Lib/site-packages/aiohttp/compression_utils.py |    319 [31m-[m
 .../venv/Lib/site-packages/aiohttp/connector.py    |   1834 [31m-[m
 .../venv/Lib/site-packages/aiohttp/cookiejar.py    |    522 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/formdata.py |    179 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/hdrs.py     |    121 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/helpers.py  |    986 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/http.py     |     72 [31m-[m
 .../Lib/site-packages/aiohttp/http_exceptions.py   |    112 [31m-[m
 .../venv/Lib/site-packages/aiohttp/http_parser.py  |   1065 [31m-[m
 .../Lib/site-packages/aiohttp/http_websocket.py    |     36 [31m-[m
 .../venv/Lib/site-packages/aiohttp/http_writer.py  |    378 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/log.py      |      8 [31m-[m
 .../venv/Lib/site-packages/aiohttp/multipart.py    |   1145 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/payload.py  |   1120 [31m-[m
 .../Lib/site-packages/aiohttp/payload_streamer.py  |     78 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/py.typed    |      1 [31m-[m
 .../Lib/site-packages/aiohttp/pytest_plugin.py     |    444 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/resolver.py |    274 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/streams.py  |    735 [31m-[m
 .../venv/Lib/site-packages/aiohttp/tcp_helpers.py  |     37 [31m-[m
 .../venv/Lib/site-packages/aiohttp/test_utils.py   |    774 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/tracing.py  |    455 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/typedefs.py |     69 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/web.py      |    592 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/web_app.py  |    620 [31m-[m
 .../Lib/site-packages/aiohttp/web_exceptions.py    |    452 [31m-[m
 .../Lib/site-packages/aiohttp/web_fileresponse.py  |    418 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/web_log.py  |    216 [31m-[m
 .../Lib/site-packages/aiohttp/web_middlewares.py   |    121 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_protocol.py |    792 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_request.py  |    916 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_response.py |    856 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_routedef.py |    214 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_runner.py   |    399 [31m-[m
 .../venv/Lib/site-packages/aiohttp/web_server.py   |     84 [31m-[m
 .../Lib/site-packages/aiohttp/web_urldispatcher.py |   1305 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/web_ws.py   |    631 [31m-[m
 backend/venv/Lib/site-packages/aiohttp/worker.py   |    255 [31m-[m
 .../aiosignal-1.4.0.dist-info/INSTALLER            |      1 [31m-[m
 .../aiosignal-1.4.0.dist-info/METADATA             |    112 [31m-[m
 .../site-packages/aiosignal-1.4.0.dist-info/RECORD |      9 [31m-[m
 .../site-packages/aiosignal-1.4.0.dist-info/WHEEL  |      5 [31m-[m
 .../aiosignal-1.4.0.dist-info/licenses/LICENSE     |    201 [31m-[m
 .../aiosignal-1.4.0.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/aiosignal/__init__.py   |     59 [31m-[m
 .../aiosignal/__pycache__/__init__.cpython-312.pyc |    Bin [31m2669[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/aiosignal/py.typed  |      0
 .../aiosqlite-0.22.1.dist-info/INSTALLER           |      1 [31m-[m
 .../aiosqlite-0.22.1.dist-info/METADATA            |    123 [31m-[m
 .../aiosqlite-0.22.1.dist-info/RECORD              |     27 [31m-[m
 .../aiosqlite-0.22.1.dist-info/REQUESTED           |      0
 .../site-packages/aiosqlite-0.22.1.dist-info/WHEEL |      4 [31m-[m
 .../aiosqlite-0.22.1.dist-info/licenses/LICENSE    |     21 [31m-[m
 .../venv/Lib/site-packages/aiosqlite/__init__.py   |     44 [31m-[m
 .../aiosqlite/__pycache__/__init__.cpython-312.pyc |    Bin [31m856[m -> [32m0[m bytes
 .../__pycache__/__version__.cpython-312.pyc        |    Bin [31m349[m -> [32m0[m bytes
 .../aiosqlite/__pycache__/context.cpython-312.pyc  |    Bin [31m3177[m -> [32m0[m bytes
 .../aiosqlite/__pycache__/core.cpython-312.pyc     |    Bin [31m23013[m -> [32m0[m bytes
 .../aiosqlite/__pycache__/cursor.cpython-312.pyc   |    Bin [31m6932[m -> [32m0[m bytes
 .../Lib/site-packages/aiosqlite/__version__.py     |      7 [31m-[m
 .../venv/Lib/site-packages/aiosqlite/context.py    |     56 [31m-[m
 backend/venv/Lib/site-packages/aiosqlite/core.py   |    468 [31m-[m
 backend/venv/Lib/site-packages/aiosqlite/cursor.py |    110 [31m-[m
 backend/venv/Lib/site-packages/aiosqlite/py.typed  |      0
 .../Lib/site-packages/aiosqlite/tests/__init__.py  |      4 [31m-[m
 .../Lib/site-packages/aiosqlite/tests/__main__.py  |      7 [31m-[m
 .../tests/__pycache__/__init__.cpython-312.pyc     |    Bin [31m221[m -> [32m0[m bytes
 .../tests/__pycache__/__main__.cpython-312.pyc     |    Bin [31m353[m -> [32m0[m bytes
 .../tests/__pycache__/helpers.cpython-312.pyc      |    Bin [31m1454[m -> [32m0[m bytes
 .../tests/__pycache__/perf.cpython-312.pyc         |    Bin [31m14260[m -> [32m0[m bytes
 .../tests/__pycache__/smoke.cpython-312.pyc        |    Bin [31m44834[m -> [32m0[m bytes
 .../Lib/site-packages/aiosqlite/tests/helpers.py   |     29 [31m-[m
 .../venv/Lib/site-packages/aiosqlite/tests/perf.py |    221 [31m-[m
 .../Lib/site-packages/aiosqlite/tests/smoke.py     |    537 [31m-[m
 .../alembic-1.17.2.dist-info/INSTALLER             |      1 [31m-[m
 .../alembic-1.17.2.dist-info/METADATA              |    139 [31m-[m
 .../site-packages/alembic-1.17.2.dist-info/RECORD  |    163 [31m-[m
 .../alembic-1.17.2.dist-info/REQUESTED             |      0
 .../site-packages/alembic-1.17.2.dist-info/WHEEL   |      5 [31m-[m
 .../alembic-1.17.2.dist-info/entry_points.txt      |      2 [31m-[m
 .../alembic-1.17.2.dist-info/licenses/LICENSE      |     19 [31m-[m
 .../alembic-1.17.2.dist-info/top_level.txt         |      1 [31m-[m
 backend/venv/Lib/site-packages/alembic/__init__.py |      4 [31m-[m
 backend/venv/Lib/site-packages/alembic/__main__.py |      4 [31m-[m
 .../alembic/__pycache__/__init__.cpython-312.pyc   |    Bin [31m260[m -> [32m0[m bytes
 .../alembic/__pycache__/__main__.cpython-312.pyc   |    Bin [31m295[m -> [32m0[m bytes
 .../alembic/__pycache__/command.cpython-312.pyc    |    Bin [31m29896[m -> [32m0[m bytes
 .../alembic/__pycache__/config.cpython-312.pyc     |    Bin [31m38644[m -> [32m0[m bytes
 .../alembic/__pycache__/context.cpython-312.pyc    |    Bin [31m360[m -> [32m0[m bytes
 .../__pycache__/environment.cpython-312.pyc        |    Bin [31m213[m -> [32m0[m bytes
 .../alembic/__pycache__/migration.cpython-312.pyc  |    Bin [31m209[m -> [32m0[m bytes
 .../alembic/__pycache__/op.cpython-312.pyc         |    Bin [31m342[m -> [32m0[m bytes
 .../site-packages/alembic/autogenerate/__init__.py |     10 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m608[m -> [32m0[m bytes
 .../autogenerate/__pycache__/api.cpython-312.pyc   |    Bin [31m22412[m -> [32m0[m bytes
 .../__pycache__/compare.cpython-312.pyc            |    Bin [31m47361[m -> [32m0[m bytes
 .../__pycache__/render.cpython-312.pyc             |    Bin [31m47403[m -> [32m0[m bytes
 .../__pycache__/rewriter.cpython-312.pyc           |    Bin [31m9483[m -> [32m0[m bytes
 .../Lib/site-packages/alembic/autogenerate/api.py  |    650 [31m-[m
 .../site-packages/alembic/autogenerate/compare.py  |   1370 [31m-[m
 .../site-packages/alembic/autogenerate/render.py   |   1172 [31m-[m
 .../site-packages/alembic/autogenerate/rewriter.py |    240 [31m-[m
 backend/venv/Lib/site-packages/alembic/command.py  |    848 [31m-[m
 backend/venv/Lib/site-packages/alembic/config.py   |   1037 [31m-[m
 backend/venv/Lib/site-packages/alembic/context.py  |      5 [31m-[m
 backend/venv/Lib/site-packages/alembic/context.pyi |    856 [31m-[m
 .../venv/Lib/site-packages/alembic/ddl/__init__.py |      6 [31m-[m
 .../ddl/__pycache__/__init__.cpython-312.pyc       |    Bin [31m370[m -> [32m0[m bytes
 .../ddl/__pycache__/_autogen.cpython-312.pyc       |    Bin [31m15180[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/base.cpython-312.pyc   |    Bin [31m16129[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/impl.cpython-312.pyc   |    Bin [31m35311[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/mssql.cpython-312.pyc  |    Bin [31m16134[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/mysql.cpython-312.pyc  |    Bin [31m16981[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/oracle.cpython-312.pyc |    Bin [31m8501[m -> [32m0[m bytes
 .../ddl/__pycache__/postgresql.cpython-312.pyc     |    Bin [31m33494[m -> [32m0[m bytes
 .../alembic/ddl/__pycache__/sqlite.cpython-312.pyc |    Bin [31m8027[m -> [32m0[m bytes
 .../venv/Lib/site-packages/alembic/ddl/_autogen.py |    329 [31m-[m
 backend/venv/Lib/site-packages/alembic/ddl/base.py |    364 [31m-[m
 backend/venv/Lib/site-packages/alembic/ddl/impl.py |    902 [31m-[m
 .../venv/Lib/site-packages/alembic/ddl/mssql.py    |    435 [31m-[m
 .../venv/Lib/site-packages/alembic/ddl/mysql.py    |    524 [31m-[m
 .../venv/Lib/site-packages/alembic/ddl/oracle.py   |    202 [31m-[m
 .../Lib/site-packages/alembic/ddl/postgresql.py    |    854 [31m-[m
 .../venv/Lib/site-packages/alembic/ddl/sqlite.py   |    237 [31m-[m
 .../venv/Lib/site-packages/alembic/environment.py  |      1 [31m-[m
 .../venv/Lib/site-packages/alembic/migration.py    |      1 [31m-[m
 backend/venv/Lib/site-packages/alembic/op.py       |      5 [31m-[m
 backend/venv/Lib/site-packages/alembic/op.pyi      |   1356 [31m-[m
 .../site-packages/alembic/operations/__init__.py   |     15 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m470[m -> [32m0[m bytes
 .../operations/__pycache__/base.cpython-312.pyc    |    Bin [31m79048[m -> [32m0[m bytes
 .../operations/__pycache__/batch.cpython-312.pyc   |    Bin [31m31380[m -> [32m0[m bytes
 .../operations/__pycache__/ops.cpython-312.pyc     |    Bin [31m111034[m -> [32m0[m bytes
 .../__pycache__/schemaobj.cpython-312.pyc          |    Bin [31m11868[m -> [32m0[m bytes
 .../operations/__pycache__/toimpl.cpython-312.pyc  |    Bin [31m11516[m -> [32m0[m bytes
 .../Lib/site-packages/alembic/operations/base.py   |   1936 [31m-[m
 .../Lib/site-packages/alembic/operations/batch.py  |    718 [31m-[m
 .../Lib/site-packages/alembic/operations/ops.py    |   2842 [31m-[m
 .../site-packages/alembic/operations/schemaobj.py  |    290 [31m-[m
 .../Lib/site-packages/alembic/operations/toimpl.py |    242 [31m-[m
 backend/venv/Lib/site-packages/alembic/py.typed    |      0
 .../Lib/site-packages/alembic/runtime/__init__.py  |      0
 .../runtime/__pycache__/__init__.cpython-312.pyc   |    Bin [31m177[m -> [32m0[m bytes
 .../__pycache__/environment.cpython-312.pyc        |    Bin [31m43789[m -> [32m0[m bytes
 .../runtime/__pycache__/migration.cpython-312.pyc  |    Bin [31m59138[m -> [32m0[m bytes
 .../site-packages/alembic/runtime/environment.py   |   1051 [31m-[m
 .../Lib/site-packages/alembic/runtime/migration.py |   1395 [31m-[m
 .../Lib/site-packages/alembic/script/__init__.py   |      4 [31m-[m
 .../script/__pycache__/__init__.cpython-312.pyc    |    Bin [31m290[m -> [32m0[m bytes
 .../script/__pycache__/base.cpython-312.pyc        |    Bin [31m42440[m -> [32m0[m bytes
 .../script/__pycache__/revision.cpython-312.pyc    |    Bin [31m62489[m -> [32m0[m bytes
 .../script/__pycache__/write_hooks.cpython-312.pyc |    Bin [31m6725[m -> [32m0[m bytes
 .../venv/Lib/site-packages/alembic/script/base.py  |   1051 [31m-[m
 .../Lib/site-packages/alembic/script/revision.py   |   1728 [31m-[m
 .../site-packages/alembic/script/write_hooks.py    |    172 [31m-[m
 .../site-packages/alembic/templates/async/README   |      1 [31m-[m
 .../async/__pycache__/env.cpython-312.pyc          |    Bin [31m3326[m -> [32m0[m bytes
 .../alembic/templates/async/alembic.ini.mako       |    147 [31m-[m
 .../site-packages/alembic/templates/async/env.py   |     89 [31m-[m
 .../alembic/templates/async/script.py.mako         |     28 [31m-[m
 .../site-packages/alembic/templates/generic/README |      1 [31m-[m
 .../generic/__pycache__/env.cpython-312.pyc        |    Bin [31m2540[m -> [32m0[m bytes
 .../alembic/templates/generic/alembic.ini.mako     |    147 [31m-[m
 .../site-packages/alembic/templates/generic/env.py |     78 [31m-[m
 .../alembic/templates/generic/script.py.mako       |     28 [31m-[m
 .../site-packages/alembic/templates/multidb/README |     12 [31m-[m
 .../multidb/__pycache__/env.cpython-312.pyc        |    Bin [31m4751[m -> [32m0[m bytes
 .../alembic/templates/multidb/alembic.ini.mako     |    155 [31m-[m
 .../site-packages/alembic/templates/multidb/env.py |    140 [31m-[m
 .../alembic/templates/multidb/script.py.mako       |     51 [31m-[m
 .../alembic/templates/pyproject/README             |      1 [31m-[m
 .../pyproject/__pycache__/env.cpython-312.pyc      |    Bin [31m2542[m -> [32m0[m bytes
 .../alembic/templates/pyproject/alembic.ini.mako   |     44 [31m-[m
 .../alembic/templates/pyproject/env.py             |     78 [31m-[m
 .../templates/pyproject/pyproject.toml.mako        |     82 [31m-[m
 .../alembic/templates/pyproject/script.py.mako     |     28 [31m-[m
 .../alembic/templates/pyproject_async/README       |      1 [31m-[m
 .../__pycache__/env.cpython-312.pyc                |    Bin [31m3336[m -> [32m0[m bytes
 .../templates/pyproject_async/alembic.ini.mako     |     44 [31m-[m
 .../alembic/templates/pyproject_async/env.py       |     89 [31m-[m
 .../templates/pyproject_async/pyproject.toml.mako  |     82 [31m-[m
 .../templates/pyproject_async/script.py.mako       |     28 [31m-[m
 .../Lib/site-packages/alembic/testing/__init__.py  |     32 [31m-[m
 .../testing/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1404[m -> [32m0[m bytes
 .../testing/__pycache__/assertions.cpython-312.pyc |    Bin [31m7415[m -> [32m0[m bytes
 .../testing/__pycache__/env.cpython-312.pyc        |    Bin [31m15695[m -> [32m0[m bytes
 .../testing/__pycache__/fixtures.cpython-312.pyc   |    Bin [31m18973[m -> [32m0[m bytes
 .../__pycache__/requirements.cpython-312.pyc       |    Bin [31m10388[m -> [32m0[m bytes
 .../__pycache__/schemacompare.cpython-312.pyc      |    Bin [31m9090[m -> [32m0[m bytes
 .../testing/__pycache__/util.cpython-312.pyc       |    Bin [31m5097[m -> [32m0[m bytes
 .../testing/__pycache__/warnings.cpython-312.pyc   |    Bin [31m1072[m -> [32m0[m bytes
 .../site-packages/alembic/testing/assertions.py    |    179 [31m-[m
 .../venv/Lib/site-packages/alembic/testing/env.py  |    557 [31m-[m
 .../Lib/site-packages/alembic/testing/fixtures.py  |    404 [31m-[m
 .../alembic/testing/plugin/__init__.py             |      0
 .../plugin/__pycache__/__init__.cpython-312.pyc    |    Bin [31m184[m -> [32m0[m bytes
 .../plugin/__pycache__/bootstrap.cpython-312.pyc   |    Bin [31m245[m -> [32m0[m bytes
 .../alembic/testing/plugin/bootstrap.py            |      4 [31m-[m
 .../site-packages/alembic/testing/requirements.py  |    189 [31m-[m
 .../site-packages/alembic/testing/schemacompare.py |    169 [31m-[m
 .../alembic/testing/suite/__init__.py              |      7 [31m-[m
 .../suite/__pycache__/__init__.cpython-312.pyc     |    Bin [31m415[m -> [32m0[m bytes
 .../__pycache__/_autogen_fixtures.cpython-312.pyc  |    Bin [31m16506[m -> [32m0[m bytes
 .../test_autogen_comments.cpython-312.pyc          |    Bin [31m6675[m -> [32m0[m bytes
 .../test_autogen_computed.cpython-312.pyc          |    Bin [31m8415[m -> [32m0[m bytes
 .../__pycache__/test_autogen_diffs.cpython-312.pyc |    Bin [31m12356[m -> [32m0[m bytes
 .../__pycache__/test_autogen_fks.cpython-312.pyc   |    Bin [31m34727[m -> [32m0[m bytes
 .../test_autogen_identity.cpython-312.pyc          |    Bin [31m9652[m -> [32m0[m bytes
 .../__pycache__/test_environment.cpython-312.pyc   |    Bin [31m18579[m -> [32m0[m bytes
 .../suite/__pycache__/test_op.cpython-312.pyc      |    Bin [31m2864[m -> [32m0[m bytes
 .../alembic/testing/suite/_autogen_fixtures.py     |    448 [31m-[m
 .../alembic/testing/suite/test_autogen_comments.py |    242 [31m-[m
 .../alembic/testing/suite/test_autogen_computed.py |    157 [31m-[m
 .../alembic/testing/suite/test_autogen_diffs.py    |    273 [31m-[m
 .../alembic/testing/suite/test_autogen_fks.py      |   1191 [31m-[m
 .../alembic/testing/suite/test_autogen_identity.py |    226 [31m-[m
 .../alembic/testing/suite/test_environment.py      |    364 [31m-[m
 .../site-packages/alembic/testing/suite/test_op.py |     42 [31m-[m
 .../venv/Lib/site-packages/alembic/testing/util.py |    126 [31m-[m
 .../Lib/site-packages/alembic/testing/warnings.py  |     31 [31m-[m
 .../Lib/site-packages/alembic/util/__init__.py     |     30 [31m-[m
 .../util/__pycache__/__init__.cpython-312.pyc      |    Bin [31m1323[m -> [32m0[m bytes
 .../util/__pycache__/compat.cpython-312.pyc        |    Bin [31m5207[m -> [32m0[m bytes
 .../util/__pycache__/editor.cpython-312.pyc        |    Bin [31m3209[m -> [32m0[m bytes
 .../alembic/util/__pycache__/exc.cpython-312.pyc   |    Bin [31m1781[m -> [32m0[m bytes
 .../util/__pycache__/langhelpers.cpython-312.pyc   |    Bin [31m14037[m -> [32m0[m bytes
 .../util/__pycache__/messaging.cpython-312.pyc     |    Bin [31m5130[m -> [32m0[m bytes
 .../util/__pycache__/pyfiles.cpython-312.pyc       |    Bin [31m6363[m -> [32m0[m bytes
 .../util/__pycache__/sqla_compat.cpython-312.pyc   |    Bin [31m20625[m -> [32m0[m bytes
 .../venv/Lib/site-packages/alembic/util/compat.py  |    130 [31m-[m
 .../venv/Lib/site-packages/alembic/util/editor.py  |     81 [31m-[m
 backend/venv/Lib/site-packages/alembic/util/exc.py |     43 [31m-[m
 .../Lib/site-packages/alembic/util/langhelpers.py  |    337 [31m-[m
 .../Lib/site-packages/alembic/util/messaging.py    |    122 [31m-[m
 .../venv/Lib/site-packages/alembic/util/pyfiles.py |    153 [31m-[m
 .../Lib/site-packages/alembic/util/sqla_compat.py  |    503 [31m-[m
 .../annotated_doc-0.0.4.dist-info/INSTALLER        |      1 [31m-[m
 .../annotated_doc-0.0.4.dist-info/METADATA         |    145 [31m-[m
 .../annotated_doc-0.0.4.dist-info/RECORD           |     11 [31m-[m
 .../annotated_doc-0.0.4.dist-info/WHEEL            |      4 [31m-[m
 .../annotated_doc-0.0.4.dist-info/entry_points.txt |      4 [31m-[m
 .../annotated_doc-0.0.4.dist-info/licenses/LICENSE |     21 [31m-[m
 .../Lib/site-packages/annotated_doc/__init__.py    |      3 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m239[m -> [32m0[m bytes
 .../annotated_doc/__pycache__/main.cpython-312.pyc |    Bin [31m1887[m -> [32m0[m bytes
 .../venv/Lib/site-packages/annotated_doc/main.py   |     36 [31m-[m
 .../venv/Lib/site-packages/annotated_doc/py.typed  |      0
 .../annotated_types-0.7.0.dist-info/INSTALLER      |      1 [31m-[m
 .../annotated_types-0.7.0.dist-info/METADATA       |    295 [31m-[m
 .../annotated_types-0.7.0.dist-info/RECORD         |     10 [31m-[m
 .../annotated_types-0.7.0.dist-info/WHEEL          |      4 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../Lib/site-packages/annotated_types/__init__.py  |    432 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m18608[m -> [32m0[m bytes
 .../__pycache__/test_cases.cpython-312.pyc         |    Bin [31m13221[m -> [32m0[m bytes
 .../Lib/site-packages/annotated_types/py.typed     |      0
 .../site-packages/annotated_types/test_cases.py    |    151 [31m-[m
 .../site-packages/anyio-4.12.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/anyio-4.12.0.dist-info/METADATA  |     96 [31m-[m
 .../site-packages/anyio-4.12.0.dist-info/RECORD    |     92 [31m-[m
 .../Lib/site-packages/anyio-4.12.0.dist-info/WHEEL |      5 [31m-[m
 .../anyio-4.12.0.dist-info/entry_points.txt        |      2 [31m-[m
 .../anyio-4.12.0.dist-info/licenses/LICENSE        |     20 [31m-[m
 .../anyio-4.12.0.dist-info/top_level.txt           |      1 [31m-[m
 backend/venv/Lib/site-packages/anyio/__init__.py   |    111 [31m-[m
 .../anyio/__pycache__/__init__.cpython-312.pyc     |    Bin [31m4611[m -> [32m0[m bytes
 .../anyio/__pycache__/from_thread.cpython-312.pyc  |    Bin [31m25784[m -> [32m0[m bytes
 .../anyio/__pycache__/functools.cpython-312.pyc    |    Bin [31m13711[m -> [32m0[m bytes
 .../anyio/__pycache__/lowlevel.cpython-312.pyc     |    Bin [31m7872[m -> [32m0[m bytes
 .../__pycache__/pytest_plugin.cpython-312.pyc      |    Bin [31m14270[m -> [32m0[m bytes
 .../__pycache__/to_interpreter.cpython-312.pyc     |    Bin [31m10314[m -> [32m0[m bytes
 .../anyio/__pycache__/to_process.cpython-312.pyc   |    Bin [31m11817[m -> [32m0[m bytes
 .../anyio/__pycache__/to_thread.cpython-312.pyc    |    Bin [31m2960[m -> [32m0[m bytes
 .../Lib/site-packages/anyio/_backends/__init__.py  |      0
 .../_backends/__pycache__/__init__.cpython-312.pyc |    Bin [31m177[m -> [32m0[m bytes
 .../_backends/__pycache__/_asyncio.cpython-312.pyc |    Bin [31m139811[m -> [32m0[m bytes
 .../_backends/__pycache__/_trio.cpython-312.pyc    |    Bin [31m73258[m -> [32m0[m bytes
 .../Lib/site-packages/anyio/_backends/_asyncio.py  |   3007 [31m-[m
 .../Lib/site-packages/anyio/_backends/_trio.py     |   1384 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/__init__.py |      0
 .../_core/__pycache__/__init__.cpython-312.pyc     |    Bin [31m173[m -> [32m0[m bytes
 .../_asyncio_selector_thread.cpython-312.pyc       |    Bin [31m8388[m -> [32m0[m bytes
 .../__pycache__/_contextmanagers.cpython-312.pyc   |    Bin [31m8983[m -> [32m0[m bytes
 .../_core/__pycache__/_eventloop.cpython-312.pyc   |    Bin [31m8292[m -> [32m0[m bytes
 .../_core/__pycache__/_exceptions.cpython-312.pyc  |    Bin [31m7250[m -> [32m0[m bytes
 .../_core/__pycache__/_fileio.cpython-312.pyc      |    Bin [31m43355[m -> [32m0[m bytes
 .../_core/__pycache__/_resources.cpython-312.pyc   |    Bin [31m915[m -> [32m0[m bytes
 .../_core/__pycache__/_signals.cpython-312.pyc     |    Bin [31m1258[m -> [32m0[m bytes
 .../_core/__pycache__/_sockets.cpython-312.pyc     |    Bin [31m39913[m -> [32m0[m bytes
 .../_core/__pycache__/_streams.cpython-312.pyc     |    Bin [31m2322[m -> [32m0[m bytes
 .../__pycache__/_subprocesses.cpython-312.pyc      |    Bin [31m9613[m -> [32m0[m bytes
 .../__pycache__/_synchronization.cpython-312.pyc   |    Bin [31m32928[m -> [32m0[m bytes
 .../anyio/_core/__pycache__/_tasks.cpython-312.pyc |    Bin [31m7114[m -> [32m0[m bytes
 .../_core/__pycache__/_tempfile.cpython-312.pyc    |    Bin [31m28117[m -> [32m0[m bytes
 .../_core/__pycache__/_testing.cpython-312.pyc     |    Bin [31m3553[m -> [32m0[m bytes
 .../_core/__pycache__/_typedattr.cpython-312.pyc   |    Bin [31m3818[m -> [32m0[m bytes
 .../anyio/_core/_asyncio_selector_thread.py        |    167 [31m-[m
 .../site-packages/anyio/_core/_contextmanagers.py  |    200 [31m-[m
 .../Lib/site-packages/anyio/_core/_eventloop.py    |    229 [31m-[m
 .../Lib/site-packages/anyio/_core/_exceptions.py   |    153 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_fileio.py  |    797 [31m-[m
 .../Lib/site-packages/anyio/_core/_resources.py    |     18 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_signals.py |     27 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_sockets.py |    991 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_streams.py |     52 [31m-[m
 .../Lib/site-packages/anyio/_core/_subprocesses.py |    202 [31m-[m
 .../site-packages/anyio/_core/_synchronization.py  |    753 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_tasks.py   |    163 [31m-[m
 .../Lib/site-packages/anyio/_core/_tempfile.py     |    616 [31m-[m
 .../venv/Lib/site-packages/anyio/_core/_testing.py |     78 [31m-[m
 .../Lib/site-packages/anyio/_core/_typedattr.py    |     81 [31m-[m
 .../venv/Lib/site-packages/anyio/abc/__init__.py   |     58 [31m-[m
 .../anyio/abc/__pycache__/__init__.cpython-312.pyc |    Bin [31m2348[m -> [32m0[m bytes
 .../abc/__pycache__/_eventloop.cpython-312.pyc     |    Bin [31m16875[m -> [32m0[m bytes
 .../abc/__pycache__/_resources.cpython-312.pyc     |    Bin [31m1620[m -> [32m0[m bytes
 .../anyio/abc/__pycache__/_sockets.cpython-312.pyc |    Bin [31m18413[m -> [32m0[m bytes
 .../anyio/abc/__pycache__/_streams.cpython-312.pyc |    Bin [31m9874[m -> [32m0[m bytes
 .../abc/__pycache__/_subprocesses.cpython-312.pyc  |    Bin [31m3228[m -> [32m0[m bytes
 .../anyio/abc/__pycache__/_tasks.cpython-312.pyc   |    Bin [31m5127[m -> [32m0[m bytes
 .../anyio/abc/__pycache__/_testing.cpython-312.pyc |    Bin [31m2823[m -> [32m0[m bytes
 .../venv/Lib/site-packages/anyio/abc/_eventloop.py |    420 [31m-[m
 .../venv/Lib/site-packages/anyio/abc/_resources.py |     33 [31m-[m
 .../venv/Lib/site-packages/anyio/abc/_sockets.py   |    405 [31m-[m
 .../venv/Lib/site-packages/anyio/abc/_streams.py   |    239 [31m-[m
 .../Lib/site-packages/anyio/abc/_subprocesses.py   |     79 [31m-[m
 backend/venv/Lib/site-packages/anyio/abc/_tasks.py |    117 [31m-[m
 .../venv/Lib/site-packages/anyio/abc/_testing.py   |     65 [31m-[m
 .../venv/Lib/site-packages/anyio/from_thread.py    |    570 [31m-[m
 backend/venv/Lib/site-packages/anyio/functools.py  |    347 [31m-[m
 backend/venv/Lib/site-packages/anyio/lowlevel.py   |    195 [31m-[m
 backend/venv/Lib/site-packages/anyio/py.typed      |      0
 .../venv/Lib/site-packages/anyio/pytest_plugin.py  |    302 [31m-[m
 .../Lib/site-packages/anyio/streams/__init__.py    |      0
 .../streams/__pycache__/__init__.cpython-312.pyc   |    Bin [31m175[m -> [32m0[m bytes
 .../streams/__pycache__/buffered.cpython-312.pyc   |    Bin [31m9054[m -> [32m0[m bytes
 .../anyio/streams/__pycache__/file.cpython-312.pyc |    Bin [31m7549[m -> [32m0[m bytes
 .../streams/__pycache__/memory.cpython-312.pyc     |    Bin [31m14996[m -> [32m0[m bytes
 .../streams/__pycache__/stapled.cpython-312.pyc    |    Bin [31m7525[m -> [32m0[m bytes
 .../anyio/streams/__pycache__/text.cpython-312.pyc |    Bin [31m9321[m -> [32m0[m bytes
 .../anyio/streams/__pycache__/tls.cpython-312.pyc  |    Bin [31m20206[m -> [32m0[m bytes
 .../Lib/site-packages/anyio/streams/buffered.py    |    188 [31m-[m
 .../venv/Lib/site-packages/anyio/streams/file.py   |    154 [31m-[m
 .../venv/Lib/site-packages/anyio/streams/memory.py |    325 [31m-[m
 .../Lib/site-packages/anyio/streams/stapled.py     |    147 [31m-[m
 .../venv/Lib/site-packages/anyio/streams/text.py   |    176 [31m-[m
 .../venv/Lib/site-packages/anyio/streams/tls.py    |    424 [31m-[m
 .../venv/Lib/site-packages/anyio/to_interpreter.py |    246 [31m-[m
 backend/venv/Lib/site-packages/anyio/to_process.py |    264 [31m-[m
 backend/venv/Lib/site-packages/anyio/to_thread.py  |     74 [31m-[m
 .../venv/Lib/site-packages/apiclient/__init__.py   |     27 [31m-[m
 .../apiclient/__pycache__/__init__.cpython-312.pyc |    Bin [31m840[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/argon2/__init__.py  |     79 [31m-[m
 backend/venv/Lib/site-packages/argon2/__main__.py  |     91 [31m-[m
 .../argon2/__pycache__/__init__.cpython-312.pyc    |    Bin [31m2181[m -> [32m0[m bytes
 .../argon2/__pycache__/__main__.cpython-312.pyc    |    Bin [31m3515[m -> [32m0[m bytes
 .../argon2/__pycache__/_legacy.cpython-312.pyc     |    Bin [31m3084[m -> [32m0[m bytes
 .../__pycache__/_password_hasher.cpython-312.pyc   |    Bin [31m10790[m -> [32m0[m bytes
 .../argon2/__pycache__/_utils.cpython-312.pyc      |    Bin [31m5539[m -> [32m0[m bytes
 .../argon2/__pycache__/exceptions.cpython-312.pyc  |    Bin [31m2011[m -> [32m0[m bytes
 .../argon2/__pycache__/low_level.cpython-312.pyc   |    Bin [31m7696[m -> [32m0[m bytes
 .../argon2/__pycache__/profiles.cpython-312.pyc    |    Bin [31m1673[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/argon2/_legacy.py   |     92 [31m-[m
 .../Lib/site-packages/argon2/_password_hasher.py   |    287 [31m-[m
 backend/venv/Lib/site-packages/argon2/_utils.py    |    174 [31m-[m
 .../venv/Lib/site-packages/argon2/exceptions.py    |     66 [31m-[m
 backend/venv/Lib/site-packages/argon2/low_level.py |    253 [31m-[m
 backend/venv/Lib/site-packages/argon2/profiles.py  |     79 [31m-[m
 backend/venv/Lib/site-packages/argon2/py.typed     |      0
 .../argon2_cffi-25.1.0.dist-info/INSTALLER         |      1 [31m-[m
 .../argon2_cffi-25.1.0.dist-info/METADATA          |    105 [31m-[m
 .../argon2_cffi-25.1.0.dist-info/RECORD            |     23 [31m-[m
 .../argon2_cffi-25.1.0.dist-info/REQUESTED         |      0
 .../argon2_cffi-25.1.0.dist-info/WHEEL             |      4 [31m-[m
 .../argon2_cffi-25.1.0.dist-info/licenses/LICENSE  |     21 [31m-[m
 .../INSTALLER                                      |      1 [31m-[m
 .../argon2_cffi_bindings-25.1.0.dist-info/METADATA |    153 [31m-[m
 .../argon2_cffi_bindings-25.1.0.dist-info/RECORD   |     11 [31m-[m
 .../argon2_cffi_bindings-25.1.0.dist-info/WHEEL    |      5 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../top_level.txt                                  |      2 [31m-[m
 backend/venv/Lib/site-packages/attr/__init__.py    |    104 [31m-[m
 backend/venv/Lib/site-packages/attr/__init__.pyi   |    389 [31m-[m
 .../attr/__pycache__/__init__.cpython-312.pyc      |    Bin [31m2603[m -> [32m0[m bytes
 .../attr/__pycache__/_cmp.cpython-312.pyc          |    Bin [31m5068[m -> [32m0[m bytes
 .../attr/__pycache__/_compat.cpython-312.pyc       |    Bin [31m3624[m -> [32m0[m bytes
 .../attr/__pycache__/_config.cpython-312.pyc       |    Bin [31m1099[m -> [32m0[m bytes
 .../attr/__pycache__/_funcs.cpython-312.pyc        |    Bin [31m14024[m -> [32m0[m bytes
 .../attr/__pycache__/_make.cpython-312.pyc         |    Bin [31m107008[m -> [32m0[m bytes
 .../attr/__pycache__/_next_gen.cpython-312.pyc     |    Bin [31m26352[m -> [32m0[m bytes
 .../attr/__pycache__/_version_info.cpython-312.pyc |    Bin [31m3408[m -> [32m0[m bytes
 .../attr/__pycache__/converters.cpython-312.pyc    |    Bin [31m4617[m -> [32m0[m bytes
 .../attr/__pycache__/exceptions.cpython-312.pyc    |    Bin [31m3570[m -> [32m0[m bytes
 .../attr/__pycache__/filters.cpython-312.pyc       |    Bin [31m2987[m -> [32m0[m bytes
 .../attr/__pycache__/setters.cpython-312.pyc       |    Bin [31m1899[m -> [32m0[m bytes
 .../attr/__pycache__/validators.cpython-312.pyc    |    Bin [31m27496[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/attr/_cmp.py        |    160 [31m-[m
 backend/venv/Lib/site-packages/attr/_cmp.pyi       |     13 [31m-[m
 backend/venv/Lib/site-packages/attr/_compat.py     |     99 [31m-[m
 backend/venv/Lib/site-packages/attr/_config.py     |     31 [31m-[m
 backend/venv/Lib/site-packages/attr/_funcs.py      |    497 [31m-[m
 backend/venv/Lib/site-packages/attr/_make.py       |   3362 [31m-[m
 backend/venv/Lib/site-packages/attr/_next_gen.py   |    674 [31m-[m
 .../venv/Lib/site-packages/attr/_typing_compat.pyi |     15 [31m-[m
 .../venv/Lib/site-packages/attr/_version_info.py   |     89 [31m-[m
 .../venv/Lib/site-packages/attr/_version_info.pyi  |      9 [31m-[m
 backend/venv/Lib/site-packages/attr/converters.py  |    162 [31m-[m
 backend/venv/Lib/site-packages/attr/converters.pyi |     19 [31m-[m
 backend/venv/Lib/site-packages/attr/exceptions.py  |     95 [31m-[m
 backend/venv/Lib/site-packages/attr/exceptions.pyi |     17 [31m-[m
 backend/venv/Lib/site-packages/attr/filters.py     |     72 [31m-[m
 backend/venv/Lib/site-packages/attr/filters.pyi    |      6 [31m-[m
 backend/venv/Lib/site-packages/attr/py.typed       |      0
 backend/venv/Lib/site-packages/attr/setters.py     |     79 [31m-[m
 backend/venv/Lib/site-packages/attr/setters.pyi    |     20 [31m-[m
 backend/venv/Lib/site-packages/attr/validators.py  |    748 [31m-[m
 backend/venv/Lib/site-packages/attr/validators.pyi |    140 [31m-[m
 .../site-packages/attrs-25.4.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/attrs-25.4.0.dist-info/METADATA  |    235 [31m-[m
 .../site-packages/attrs-25.4.0.dist-info/RECORD    |     55 [31m-[m
 .../Lib/site-packages/attrs-25.4.0.dist-info/WHEEL |      4 [31m-[m
 .../attrs-25.4.0.dist-info/licenses/LICENSE        |     21 [31m-[m
 backend/venv/Lib/site-packages/attrs/__init__.py   |     72 [31m-[m
 backend/venv/Lib/site-packages/attrs/__init__.pyi  |    314 [31m-[m
 .../attrs/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1200[m -> [32m0[m bytes
 .../attrs/__pycache__/converters.cpython-312.pyc   |    Bin [31m208[m -> [32m0[m bytes
 .../attrs/__pycache__/exceptions.cpython-312.pyc   |    Bin [31m208[m -> [32m0[m bytes
 .../attrs/__pycache__/filters.cpython-312.pyc      |    Bin [31m202[m -> [32m0[m bytes
 .../attrs/__pycache__/setters.cpython-312.pyc      |    Bin [31m202[m -> [32m0[m bytes
 .../attrs/__pycache__/validators.cpython-312.pyc   |    Bin [31m208[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/attrs/converters.py |      3 [31m-[m
 backend/venv/Lib/site-packages/attrs/exceptions.py |      3 [31m-[m
 backend/venv/Lib/site-packages/attrs/filters.py    |      3 [31m-[m
 backend/venv/Lib/site-packages/attrs/py.typed      |      0
 backend/venv/Lib/site-packages/attrs/setters.py    |      3 [31m-[m
 backend/venv/Lib/site-packages/attrs/validators.py |      3 [31m-[m
 .../site-packages/bcrypt-5.0.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/bcrypt-5.0.0.dist-info/LICENSE   |    201 [31m-[m
 .../site-packages/bcrypt-5.0.0.dist-info/METADATA  |    342 [31m-[m
 .../site-packages/bcrypt-5.0.0.dist-info/RECORD    |     11 [31m-[m
 .../Lib/site-packages/bcrypt-5.0.0.dist-info/WHEEL |      5 [31m-[m
 .../bcrypt-5.0.0.dist-info/top_level.txt           |      1 [31m-[m
 backend/venv/Lib/site-packages/bcrypt/__init__.py  |     43 [31m-[m
 backend/venv/Lib/site-packages/bcrypt/__init__.pyi |     10 [31m-[m
 .../bcrypt/__pycache__/__init__.cpython-312.pyc    |    Bin [31m562[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/bcrypt/_bcrypt.pyd  |    Bin [31m305152[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/bcrypt/py.typed     |      0
 .../beautifulsoup4-4.14.3.dist-info/INSTALLER      |      1 [31m-[m
 .../beautifulsoup4-4.14.3.dist-info/METADATA       |    123 [31m-[m
 .../beautifulsoup4-4.14.3.dist-info/RECORD         |     38 [31m-[m
 .../beautifulsoup4-4.14.3.dist-info/REQUESTED      |      0
 .../beautifulsoup4-4.14.3.dist-info/WHEEL          |      4 [31m-[m
 .../licenses/AUTHORS                               |     49 [31m-[m
 .../licenses/LICENSE                               |     31 [31m-[m
 backend/venv/Lib/site-packages/bs4/__init__.py     |   1174 [31m-[m
 .../bs4/__pycache__/__init__.cpython-312.pyc       |    Bin [31m39798[m -> [32m0[m bytes
 .../bs4/__pycache__/_deprecation.cpython-312.pyc   |    Bin [31m3733[m -> [32m0[m bytes
 .../bs4/__pycache__/_typing.cpython-312.pyc        |    Bin [31m3896[m -> [32m0[m bytes
 .../bs4/__pycache__/_warnings.cpython-312.pyc      |    Bin [31m5586[m -> [32m0[m bytes
 .../bs4/__pycache__/css.cpython-312.pyc            |    Bin [31m14450[m -> [32m0[m bytes
 .../bs4/__pycache__/dammit.cpython-312.pyc         |    Bin [31m48290[m -> [32m0[m bytes
 .../bs4/__pycache__/diagnose.cpython-312.pyc       |    Bin [31m12605[m -> [32m0[m bytes
 .../bs4/__pycache__/element.cpython-312.pyc        |    Bin [31m115842[m -> [32m0[m bytes
 .../bs4/__pycache__/exceptions.cpython-312.pyc     |    Bin [31m1749[m -> [32m0[m bytes
 .../bs4/__pycache__/filter.cpython-312.pyc         |    Bin [31m28689[m -> [32m0[m bytes
 .../bs4/__pycache__/formatter.cpython-312.pyc      |    Bin [31m10517[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/bs4/_deprecation.py |     80 [31m-[m
 backend/venv/Lib/site-packages/bs4/_typing.py      |    205 [31m-[m
 backend/venv/Lib/site-packages/bs4/_warnings.py    |     98 [31m-[m
 .../venv/Lib/site-packages/bs4/builder/__init__.py |    848 [31m-[m
 .../builder/__pycache__/__init__.cpython-312.pyc   |    Bin [31m27445[m -> [32m0[m bytes
 .../builder/__pycache__/_html5lib.cpython-312.pyc  |    Bin [31m23772[m -> [32m0[m bytes
 .../__pycache__/_htmlparser.cpython-312.pyc        |    Bin [31m14517[m -> [32m0[m bytes
 .../bs4/builder/__pycache__/_lxml.cpython-312.pyc  |    Bin [31m18612[m -> [32m0[m bytes
 .../Lib/site-packages/bs4/builder/_html5lib.py     |    611 [31m-[m
 .../Lib/site-packages/bs4/builder/_htmlparser.py   |    462 [31m-[m
 .../venv/Lib/site-packages/bs4/builder/_lxml.py    |    501 [31m-[m
 backend/venv/Lib/site-packages/bs4/css.py          |    339 [31m-[m
 backend/venv/Lib/site-packages/bs4/dammit.py       |   1516 [31m-[m
 backend/venv/Lib/site-packages/bs4/diagnose.py     |    268 [31m-[m
 backend/venv/Lib/site-packages/bs4/element.py      |   3211 [31m-[m
 backend/venv/Lib/site-packages/bs4/exceptions.py   |     28 [31m-[m
 backend/venv/Lib/site-packages/bs4/filter.py       |    764 [31m-[m
 backend/venv/Lib/site-packages/bs4/formatter.py    |    276 [31m-[m
 backend/venv/Lib/site-packages/bs4/py.typed        |      0
 .../cachetools-6.2.4.dist-info/INSTALLER           |      1 [31m-[m
 .../cachetools-6.2.4.dist-info/METADATA            |    155 [31m-[m
 .../cachetools-6.2.4.dist-info/RECORD              |     16 [31m-[m
 .../site-packages/cachetools-6.2.4.dist-info/WHEEL |      5 [31m-[m
 .../cachetools-6.2.4.dist-info/licenses/LICENSE    |     20 [31m-[m
 .../cachetools-6.2.4.dist-info/top_level.txt       |      1 [31m-[m
 .../venv/Lib/site-packages/cachetools/__init__.py  |    719 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m36086[m -> [32m0[m bytes
 .../cachetools/__pycache__/_cached.cpython-312.pyc |    Bin [31m11133[m -> [32m0[m bytes
 .../__pycache__/_cachedmethod.cpython-312.pyc      |    Bin [31m5959[m -> [32m0[m bytes
 .../cachetools/__pycache__/func.cpython-312.pyc    |    Bin [31m4627[m -> [32m0[m bytes
 .../cachetools/__pycache__/keys.cpython-312.pyc    |    Bin [31m3203[m -> [32m0[m bytes
 .../venv/Lib/site-packages/cachetools/_cached.py   |    250 [31m-[m
 .../Lib/site-packages/cachetools/_cachedmethod.py  |    128 [31m-[m
 backend/venv/Lib/site-packages/cachetools/func.py  |    102 [31m-[m
 backend/venv/Lib/site-packages/cachetools/keys.py  |     63 [31m-[m
 .../certifi-2025.11.12.dist-info/INSTALLER         |      1 [31m-[m
 .../certifi-2025.11.12.dist-info/METADATA          |     78 [31m-[m
 .../certifi-2025.11.12.dist-info/RECORD            |     14 [31m-[m
 .../certifi-2025.11.12.dist-info/WHEEL             |      5 [31m-[m
 .../certifi-2025.11.12.dist-info/licenses/LICENSE  |     20 [31m-[m
 .../certifi-2025.11.12.dist-info/top_level.txt     |      1 [31m-[m
 backend/venv/Lib/site-packages/certifi/__init__.py |      4 [31m-[m
 backend/venv/Lib/site-packages/certifi/__main__.py |     12 [31m-[m
 .../certifi/__pycache__/__init__.cpython-312.pyc   |    Bin [31m296[m -> [32m0[m bytes
 .../certifi/__pycache__/__main__.cpython-312.pyc   |    Bin [31m611[m -> [32m0[m bytes
 .../certifi/__pycache__/core.cpython-312.pyc       |    Bin [31m2043[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/certifi/cacert.pem  |   4678 [31m-[m
 backend/venv/Lib/site-packages/certifi/core.py     |     83 [31m-[m
 backend/venv/Lib/site-packages/certifi/py.typed    |      0
 .../site-packages/cffi-2.0.0.dist-info/INSTALLER   |      1 [31m-[m
 .../site-packages/cffi-2.0.0.dist-info/METADATA    |     68 [31m-[m
 .../Lib/site-packages/cffi-2.0.0.dist-info/RECORD  |     49 [31m-[m
 .../Lib/site-packages/cffi-2.0.0.dist-info/WHEEL   |      5 [31m-[m
 .../cffi-2.0.0.dist-info/entry_points.txt          |      2 [31m-[m
 .../cffi-2.0.0.dist-info/licenses/AUTHORS          |      8 [31m-[m
 .../cffi-2.0.0.dist-info/licenses/LICENSE          |     23 [31m-[m
 .../cffi-2.0.0.dist-info/top_level.txt             |      2 [31m-[m
 backend/venv/Lib/site-packages/cffi/__init__.py    |     14 [31m-[m
 .../cffi/__pycache__/__init__.cpython-312.pyc      |    Bin [31m534[m -> [32m0[m bytes
 .../__pycache__/_imp_emulation.cpython-312.pyc     |    Bin [31m3846[m -> [32m0[m bytes
 .../_shimmed_dist_utils.cpython-312.pyc            |    Bin [31m2070[m -> [32m0[m bytes
 .../cffi/__pycache__/api.cpython-312.pyc           |    Bin [31m50098[m -> [32m0[m bytes
 .../__pycache__/backend_ctypes.cpython-312.pyc     |    Bin [31m63491[m -> [32m0[m bytes
 .../cffi/__pycache__/cffi_opcode.cpython-312.pyc   |    Bin [31m6769[m -> [32m0[m bytes
 .../cffi/__pycache__/commontypes.cpython-312.pyc   |    Bin [31m3059[m -> [32m0[m bytes
 .../cffi/__pycache__/cparser.cpython-312.pyc       |    Bin [31m46743[m -> [32m0[m bytes
 .../cffi/__pycache__/error.cpython-312.pyc         |    Bin [31m1876[m -> [32m0[m bytes
 .../cffi/__pycache__/ffiplatform.cpython-312.pyc   |    Bin [31m5788[m -> [32m0[m bytes
 .../cffi/__pycache__/lock.cpython-312.pyc          |    Bin [31m506[m -> [32m0[m bytes
 .../cffi/__pycache__/model.cpython-312.pyc         |    Bin [31m30096[m -> [32m0[m bytes
 .../cffi/__pycache__/pkgconfig.cpython-312.pyc     |    Bin [31m6355[m -> [32m0[m bytes
 .../cffi/__pycache__/recompiler.cpython-312.pyc    |    Bin [31m80823[m -> [32m0[m bytes
 .../__pycache__/setuptools_ext.cpython-312.pyc     |    Bin [31m11235[m -> [32m0[m bytes
 .../cffi/__pycache__/vengine_cpy.cpython-312.pyc   |    Bin [31m50849[m -> [32m0[m bytes
 .../cffi/__pycache__/vengine_gen.cpython-312.pyc   |    Bin [31m34088[m -> [32m0[m bytes
 .../cffi/__pycache__/verifier.cpython-312.pyc      |    Bin [31m16125[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/cffi/_cffi_errors.h |    149 [31m-[m
 .../venv/Lib/site-packages/cffi/_cffi_include.h    |    389 [31m-[m
 backend/venv/Lib/site-packages/cffi/_embedding.h   |    550 [31m-[m
 .../venv/Lib/site-packages/cffi/_imp_emulation.py  |     83 [31m-[m
 .../Lib/site-packages/cffi/_shimmed_dist_utils.py  |     45 [31m-[m
 backend/venv/Lib/site-packages/cffi/api.py         |    967 [31m-[m
 .../venv/Lib/site-packages/cffi/backend_ctypes.py  |   1121 [31m-[m
 backend/venv/Lib/site-packages/cffi/cffi_opcode.py |    187 [31m-[m
 backend/venv/Lib/site-packages/cffi/commontypes.py |     82 [31m-[m
 backend/venv/Lib/site-packages/cffi/cparser.py     |   1015 [31m-[m
 backend/venv/Lib/site-packages/cffi/error.py       |     31 [31m-[m
 backend/venv/Lib/site-packages/cffi/ffiplatform.py |    113 [31m-[m
 backend/venv/Lib/site-packages/cffi/lock.py        |     30 [31m-[m
 backend/venv/Lib/site-packages/cffi/model.py       |    618 [31m-[m
 backend/venv/Lib/site-packages/cffi/parse_c_type.h |    181 [31m-[m
 backend/venv/Lib/site-packages/cffi/pkgconfig.py   |    121 [31m-[m
 backend/venv/Lib/site-packages/cffi/recompiler.py  |   1598 [31m-[m
 .../venv/Lib/site-packages/cffi/setuptools_ext.py  |    229 [31m-[m
 backend/venv/Lib/site-packages/cffi/vengine_cpy.py |   1087 [31m-[m
 backend/venv/Lib/site-packages/cffi/vengine_gen.py |    679 [31m-[m
 backend/venv/Lib/site-packages/cffi/verifier.py    |    306 [31m-[m
 .../charset_normalizer-3.4.4.dist-info/INSTALLER   |      1 [31m-[m
 .../charset_normalizer-3.4.4.dist-info/METADATA    |    764 [31m-[m
 .../charset_normalizer-3.4.4.dist-info/RECORD      |     35 [31m-[m
 .../charset_normalizer-3.4.4.dist-info/WHEEL       |      5 [31m-[m
 .../entry_points.txt                               |      2 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../site-packages/charset_normalizer/__init__.py   |     48 [31m-[m
 .../site-packages/charset_normalizer/__main__.py   |      6 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1762[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m337[m -> [32m0[m bytes
 .../__pycache__/api.cpython-312.pyc                |    Bin [31m18145[m -> [32m0[m bytes
 .../__pycache__/cd.cpython-312.pyc                 |    Bin [31m13224[m -> [32m0[m bytes
 .../__pycache__/constant.cpython-312.pyc           |    Bin [31m40792[m -> [32m0[m bytes
 .../__pycache__/legacy.cpython-312.pyc             |    Bin [31m2992[m -> [32m0[m bytes
 .../__pycache__/md.cpython-312.pyc                 |    Bin [31m24318[m -> [32m0[m bytes
 .../__pycache__/models.cpython-312.pyc             |    Bin [31m17105[m -> [32m0[m bytes
 .../__pycache__/utils.cpython-312.pyc              |    Bin [31m13692[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m364[m -> [32m0[m bytes
 .../Lib/site-packages/charset_normalizer/api.py    |    669 [31m-[m
 .../Lib/site-packages/charset_normalizer/cd.py     |    395 [31m-[m
 .../charset_normalizer/cli/__init__.py             |      8 [31m-[m
 .../charset_normalizer/cli/__main__.py             |    381 [31m-[m
 .../cli/__pycache__/__init__.cpython-312.pyc       |    Bin [31m325[m -> [32m0[m bytes
 .../cli/__pycache__/__main__.cpython-312.pyc       |    Bin [31m14375[m -> [32m0[m bytes
 .../site-packages/charset_normalizer/constant.py   |   2015 [31m-[m
 .../Lib/site-packages/charset_normalizer/legacy.py |     80 [31m-[m
 .../charset_normalizer/md.cp312-win_amd64.pyd      |    Bin [31m10752[m -> [32m0[m bytes
 .../Lib/site-packages/charset_normalizer/md.py     |    635 [31m-[m
 .../md__mypyc.cp312-win_amd64.pyd                  |    Bin [31m126976[m -> [32m0[m bytes
 .../Lib/site-packages/charset_normalizer/models.py |    360 [31m-[m
 .../Lib/site-packages/charset_normalizer/py.typed  |      0
 .../Lib/site-packages/charset_normalizer/utils.py  |    414 [31m-[m
 .../site-packages/charset_normalizer/version.py    |      8 [31m-[m
 .../site-packages/click-8.3.1.dist-info/INSTALLER  |      1 [31m-[m
 .../site-packages/click-8.3.1.dist-info/METADATA   |     84 [31m-[m
 .../Lib/site-packages/click-8.3.1.dist-info/RECORD |     40 [31m-[m
 .../Lib/site-packages/click-8.3.1.dist-info/WHEEL  |      4 [31m-[m
 .../click-8.3.1.dist-info/licenses/LICENSE.txt     |     28 [31m-[m
 backend/venv/Lib/site-packages/click/__init__.py   |    123 [31m-[m
 .../click/__pycache__/__init__.cpython-312.pyc     |    Bin [31m4053[m -> [32m0[m bytes
 .../click/__pycache__/_compat.cpython-312.pyc      |    Bin [31m24172[m -> [32m0[m bytes
 .../click/__pycache__/_termui_impl.cpython-312.pyc |    Bin [31m31541[m -> [32m0[m bytes
 .../click/__pycache__/_textwrap.cpython-312.pyc    |    Bin [31m2401[m -> [32m0[m bytes
 .../click/__pycache__/_utils.cpython-312.pyc       |    Bin [31m1181[m -> [32m0[m bytes
 .../click/__pycache__/_winconsole.cpython-312.pyc  |    Bin [31m11746[m -> [32m0[m bytes
 .../click/__pycache__/core.cpython-312.pyc         |    Bin [31m134377[m -> [32m0[m bytes
 .../click/__pycache__/decorators.cpython-312.pyc   |    Bin [31m22118[m -> [32m0[m bytes
 .../click/__pycache__/exceptions.cpython-312.pyc   |    Bin [31m14758[m -> [32m0[m bytes
 .../click/__pycache__/formatting.cpython-312.pyc   |    Bin [31m13579[m -> [32m0[m bytes
 .../click/__pycache__/globals.cpython-312.pyc      |    Bin [31m2946[m -> [32m0[m bytes
 .../click/__pycache__/parser.cpython-312.pyc       |    Bin [31m20405[m -> [32m0[m bytes
 .../__pycache__/shell_completion.cpython-312.pyc   |    Bin [31m23280[m -> [32m0[m bytes
 .../click/__pycache__/termui.cpython-312.pyc       |    Bin [31m34633[m -> [32m0[m bytes
 .../click/__pycache__/testing.cpython-312.pyc      |    Bin [31m27375[m -> [32m0[m bytes
 .../click/__pycache__/types.cpython-312.pyc        |    Bin [31m50045[m -> [32m0[m bytes
 .../click/__pycache__/utils.cpython-312.pyc        |    Bin [31m24850[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/click/_compat.py    |    622 [31m-[m
 .../venv/Lib/site-packages/click/_termui_impl.py   |    852 [31m-[m
 backend/venv/Lib/site-packages/click/_textwrap.py  |     51 [31m-[m
 backend/venv/Lib/site-packages/click/_utils.py     |     36 [31m-[m
 .../venv/Lib/site-packages/click/_winconsole.py    |    296 [31m-[m
 backend/venv/Lib/site-packages/click/core.py       |   3415 [31m-[m
 backend/venv/Lib/site-packages/click/decorators.py |    551 [31m-[m
 backend/venv/Lib/site-packages/click/exceptions.py |    308 [31m-[m
 backend/venv/Lib/site-packages/click/formatting.py |    301 [31m-[m
 backend/venv/Lib/site-packages/click/globals.py    |     67 [31m-[m
 backend/venv/Lib/site-packages/click/parser.py     |    532 [31m-[m
 backend/venv/Lib/site-packages/click/py.typed      |      0
 .../Lib/site-packages/click/shell_completion.py    |    667 [31m-[m
 backend/venv/Lib/site-packages/click/termui.py     |    883 [31m-[m
 backend/venv/Lib/site-packages/click/testing.py    |    577 [31m-[m
 backend/venv/Lib/site-packages/click/types.py      |   1209 [31m-[m
 backend/venv/Lib/site-packages/click/utils.py      |    627 [31m-[m
 .../colorama-0.4.6.dist-info/INSTALLER             |      1 [31m-[m
 .../colorama-0.4.6.dist-info/METADATA              |    441 [31m-[m
 .../site-packages/colorama-0.4.6.dist-info/RECORD  |     31 [31m-[m
 .../site-packages/colorama-0.4.6.dist-info/WHEEL   |      5 [31m-[m
 .../colorama-0.4.6.dist-info/licenses/LICENSE.txt  |     27 [31m-[m
 .../venv/Lib/site-packages/colorama/__init__.py    |      7 [31m-[m
 .../colorama/__pycache__/__init__.cpython-312.pyc  |    Bin [31m470[m -> [32m0[m bytes
 .../colorama/__pycache__/ansi.cpython-312.pyc      |    Bin [31m3923[m -> [32m0[m bytes
 .../__pycache__/ansitowin32.cpython-312.pyc        |    Bin [31m16390[m -> [32m0[m bytes
 .../__pycache__/initialise.cpython-312.pyc         |    Bin [31m3528[m -> [32m0[m bytes
 .../colorama/__pycache__/win32.cpython-312.pyc     |    Bin [31m8113[m -> [32m0[m bytes
 .../colorama/__pycache__/winterm.cpython-312.pyc   |    Bin [31m9066[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/colorama/ansi.py    |    102 [31m-[m
 .../venv/Lib/site-packages/colorama/ansitowin32.py |    277 [31m-[m
 .../venv/Lib/site-packages/colorama/initialise.py  |    121 [31m-[m
 .../Lib/site-packages/colorama/tests/__init__.py   |      1 [31m-[m
 .../tests/__pycache__/__init__.cpython-312.pyc     |    Bin [31m176[m -> [32m0[m bytes
 .../tests/__pycache__/ansi_test.cpython-312.pyc    |    Bin [31m5445[m -> [32m0[m bytes
 .../__pycache__/ansitowin32_test.cpython-312.pyc   |    Bin [31m17984[m -> [32m0[m bytes
 .../__pycache__/initialise_test.cpython-312.pyc    |    Bin [31m11632[m -> [32m0[m bytes
 .../tests/__pycache__/isatty_test.cpython-312.pyc  |    Bin [31m4759[m -> [32m0[m bytes
 .../tests/__pycache__/utils.cpython-312.pyc        |    Bin [31m2448[m -> [32m0[m bytes
 .../tests/__pycache__/winterm_test.cpython-312.pyc |    Bin [31m6590[m -> [32m0[m bytes
 .../Lib/site-packages/colorama/tests/ansi_test.py  |     76 [31m-[m
 .../colorama/tests/ansitowin32_test.py             |    294 [31m-[m
 .../colorama/tests/initialise_test.py              |    189 [31m-[m
 .../site-packages/colorama/tests/isatty_test.py    |     57 [31m-[m
 .../venv/Lib/site-packages/colorama/tests/utils.py |     49 [31m-[m
 .../site-packages/colorama/tests/winterm_test.py   |    131 [31m-[m
 backend/venv/Lib/site-packages/colorama/win32.py   |    180 [31m-[m
 backend/venv/Lib/site-packages/colorama/winterm.py |    195 [31m-[m
 .../croniter-6.0.0.dist-info/INSTALLER             |      1 [31m-[m
 .../site-packages/croniter-6.0.0.dist-info/LICENSE |      7 [31m-[m
 .../croniter-6.0.0.dist-info/METADATA              |   1041 [31m-[m
 .../site-packages/croniter-6.0.0.dist-info/RECORD  |     10 [31m-[m
 .../site-packages/croniter-6.0.0.dist-info/WHEEL   |      6 [31m-[m
 .../croniter-6.0.0.dist-info/top_level.txt         |      1 [31m-[m
 .../venv/Lib/site-packages/croniter/__init__.py    |     25 [31m-[m
 .../croniter/__pycache__/__init__.cpython-312.pyc  |    Bin [31m785[m -> [32m0[m bytes
 .../croniter/__pycache__/croniter.cpython-312.pyc  |    Bin [31m50738[m -> [32m0[m bytes
 .../venv/Lib/site-packages/croniter/croniter.py    |   1362 [31m-[m
 .../cryptography-46.0.3.dist-info/INSTALLER        |      1 [31m-[m
 .../cryptography-46.0.3.dist-info/METADATA         |    139 [31m-[m
 .../cryptography-46.0.3.dist-info/RECORD           |    180 [31m-[m
 .../cryptography-46.0.3.dist-info/WHEEL            |      4 [31m-[m
 .../cryptography-46.0.3.dist-info/licenses/LICENSE |      3 [31m-[m
 .../licenses/LICENSE.APACHE                        |    202 [31m-[m
 .../licenses/LICENSE.BSD                           |     27 [31m-[m
 .../Lib/site-packages/cryptography/__about__.py    |     17 [31m-[m
 .../Lib/site-packages/cryptography/__init__.py     |     13 [31m-[m
 .../__pycache__/__about__.cpython-312.pyc          |    Bin [31m446[m -> [32m0[m bytes
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m356[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m2370[m -> [32m0[m bytes
 .../__pycache__/fernet.cpython-312.pyc             |    Bin [31m11100[m -> [32m0[m bytes
 .../cryptography/__pycache__/utils.cpython-312.pyc |    Bin [31m6546[m -> [32m0[m bytes
 .../Lib/site-packages/cryptography/exceptions.py   |     52 [31m-[m
 .../venv/Lib/site-packages/cryptography/fernet.py  |    224 [31m-[m
 .../site-packages/cryptography/hazmat/__init__.py  |     13 [31m-[m
 .../hazmat/__pycache__/__init__.cpython-312.pyc    |    Bin [31m237[m -> [32m0[m bytes
 .../hazmat/__pycache__/_oid.cpython-312.pyc        |    Bin [31m21027[m -> [32m0[m bytes
 .../Lib/site-packages/cryptography/hazmat/_oid.py  |    356 [31m-[m
 .../cryptography/hazmat/asn1/__init__.py           |     10 [31m-[m
 .../asn1/__pycache__/__init__.cpython-312.pyc      |    Bin [31m316[m -> [32m0[m bytes
 .../hazmat/asn1/__pycache__/asn1.cpython-312.pyc   |    Bin [31m3606[m -> [32m0[m bytes
 .../site-packages/cryptography/hazmat/asn1/asn1.py |    116 [31m-[m
 .../cryptography/hazmat/backends/__init__.py       |     13 [31m-[m
 .../backends/__pycache__/__init__.cpython-312.pyc  |    Bin [31m487[m -> [32m0[m bytes
 .../hazmat/backends/openssl/__init__.py            |      9 [31m-[m
 .../openssl/__pycache__/__init__.cpython-312.pyc   |    Bin [31m353[m -> [32m0[m bytes
 .../openssl/__pycache__/backend.cpython-312.pyc    |    Bin [31m13495[m -> [32m0[m bytes
 .../hazmat/backends/openssl/backend.py             |    302 [31m-[m
 .../cryptography/hazmat/bindings/__init__.py       |      3 [31m-[m
 .../bindings/__pycache__/__init__.cpython-312.pyc  |    Bin [31m190[m -> [32m0[m bytes
 .../cryptography/hazmat/bindings/_rust.pyd         |    Bin [31m9245696[m -> [32m0[m bytes
 .../hazmat/bindings/_rust/__init__.pyi             |     37 [31m-[m
 .../hazmat/bindings/_rust/_openssl.pyi             |      8 [31m-[m
 .../cryptography/hazmat/bindings/_rust/asn1.pyi    |      7 [31m-[m
 .../hazmat/bindings/_rust/declarative_asn1.pyi     |     32 [31m-[m
 .../hazmat/bindings/_rust/exceptions.pyi           |     17 [31m-[m
 .../cryptography/hazmat/bindings/_rust/ocsp.pyi    |    117 [31m-[m
 .../hazmat/bindings/_rust/openssl/__init__.pyi     |     75 [31m-[m
 .../hazmat/bindings/_rust/openssl/aead.pyi         |    107 [31m-[m
 .../hazmat/bindings/_rust/openssl/ciphers.pyi      |     38 [31m-[m
 .../hazmat/bindings/_rust/openssl/cmac.pyi         |     18 [31m-[m
 .../hazmat/bindings/_rust/openssl/dh.pyi           |     51 [31m-[m
 .../hazmat/bindings/_rust/openssl/dsa.pyi          |     41 [31m-[m
 .../hazmat/bindings/_rust/openssl/ec.pyi           |     52 [31m-[m
 .../hazmat/bindings/_rust/openssl/ed25519.pyi      |     13 [31m-[m
 .../hazmat/bindings/_rust/openssl/ed448.pyi        |     13 [31m-[m
 .../hazmat/bindings/_rust/openssl/hashes.pyi       |     28 [31m-[m
 .../hazmat/bindings/_rust/openssl/hmac.pyi         |     22 [31m-[m
 .../hazmat/bindings/_rust/openssl/kdf.pyi          |     72 [31m-[m
 .../hazmat/bindings/_rust/openssl/keys.pyi         |     34 [31m-[m
 .../hazmat/bindings/_rust/openssl/poly1305.pyi     |     15 [31m-[m
 .../hazmat/bindings/_rust/openssl/rsa.pyi          |     55 [31m-[m
 .../hazmat/bindings/_rust/openssl/x25519.pyi       |     13 [31m-[m
 .../hazmat/bindings/_rust/openssl/x448.pyi         |     13 [31m-[m
 .../cryptography/hazmat/bindings/_rust/pkcs12.pyi  |     52 [31m-[m
 .../cryptography/hazmat/bindings/_rust/pkcs7.pyi   |     50 [31m-[m
 .../hazmat/bindings/_rust/test_support.pyi         |     23 [31m-[m
 .../cryptography/hazmat/bindings/_rust/x509.pyi    |    301 [31m-[m
 .../hazmat/bindings/openssl/__init__.py            |      3 [31m-[m
 .../openssl/__pycache__/__init__.cpython-312.pyc   |    Bin [31m198[m -> [32m0[m bytes
 .../__pycache__/_conditional.cpython-312.pyc       |    Bin [31m5774[m -> [32m0[m bytes
 .../openssl/__pycache__/binding.cpython-312.pyc    |    Bin [31m5578[m -> [32m0[m bytes
 .../hazmat/bindings/openssl/_conditional.py        |    207 [31m-[m
 .../hazmat/bindings/openssl/binding.py             |    137 [31m-[m
 .../cryptography/hazmat/decrepit/__init__.py       |      5 [31m-[m
 .../decrepit/__pycache__/__init__.cpython-312.pyc  |    Bin [31m241[m -> [32m0[m bytes
 .../hazmat/decrepit/ciphers/__init__.py            |      5 [31m-[m
 .../ciphers/__pycache__/__init__.cpython-312.pyc   |    Bin [31m249[m -> [32m0[m bytes
 .../ciphers/__pycache__/algorithms.cpython-312.pyc |    Bin [31m4781[m -> [32m0[m bytes
 .../hazmat/decrepit/ciphers/algorithms.py          |    112 [31m-[m
 .../cryptography/hazmat/primitives/__init__.py     |      3 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m192[m -> [32m0[m bytes
 .../__pycache__/_asymmetric.cpython-312.pyc        |    Bin [31m798[m -> [32m0[m bytes
 .../__pycache__/_cipheralgorithm.cpython-312.pyc   |    Bin [31m2478[m -> [32m0[m bytes
 .../__pycache__/_serialization.cpython-312.pyc     |    Bin [31m7022[m -> [32m0[m bytes
 .../primitives/__pycache__/cmac.cpython-312.pyc    |    Bin [31m420[m -> [32m0[m bytes
 .../__pycache__/constant_time.cpython-312.pyc      |    Bin [31m658[m -> [32m0[m bytes
 .../primitives/__pycache__/hashes.cpython-312.pyc  |    Bin [31m8262[m -> [32m0[m bytes
 .../primitives/__pycache__/hmac.cpython-312.pyc    |    Bin [31m579[m -> [32m0[m bytes
 .../primitives/__pycache__/keywrap.cpython-312.pyc |    Bin [31m7448[m -> [32m0[m bytes
 .../primitives/__pycache__/padding.cpython-312.pyc |    Bin [31m3243[m -> [32m0[m bytes
 .../__pycache__/poly1305.cpython-312.pyc           |    Bin [31m432[m -> [32m0[m bytes
 .../cryptography/hazmat/primitives/_asymmetric.py  |     19 [31m-[m
 .../hazmat/primitives/_cipheralgorithm.py          |     60 [31m-[m
 .../hazmat/primitives/_serialization.py            |    168 [31m-[m
 .../hazmat/primitives/asymmetric/__init__.py       |      3 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m203[m -> [32m0[m bytes
 .../asymmetric/__pycache__/dh.cpython-312.pyc      |    Bin [31m6065[m -> [32m0[m bytes
 .../asymmetric/__pycache__/dsa.cpython-312.pyc     |    Bin [31m6911[m -> [32m0[m bytes
 .../asymmetric/__pycache__/ec.cpython-312.pyc      |    Bin [31m17819[m -> [32m0[m bytes
 .../asymmetric/__pycache__/ed25519.cpython-312.pyc |    Bin [31m5599[m -> [32m0[m bytes
 .../asymmetric/__pycache__/ed448.cpython-312.pyc   |    Bin [31m5642[m -> [32m0[m bytes
 .../asymmetric/__pycache__/padding.cpython-312.pyc |    Bin [31m4813[m -> [32m0[m bytes
 .../asymmetric/__pycache__/rsa.cpython-312.pyc     |    Bin [31m10428[m -> [32m0[m bytes
 .../asymmetric/__pycache__/types.cpython-312.pyc   |    Bin [31m3152[m -> [32m0[m bytes
 .../asymmetric/__pycache__/utils.cpython-312.pyc   |    Bin [31m1317[m -> [32m0[m bytes
 .../asymmetric/__pycache__/x25519.cpython-312.pyc  |    Bin [31m5396[m -> [32m0[m bytes
 .../asymmetric/__pycache__/x448.cpython-312.pyc    |    Bin [31m5437[m -> [32m0[m bytes
 .../hazmat/primitives/asymmetric/dh.py             |    147 [31m-[m
 .../hazmat/primitives/asymmetric/dsa.py            |    167 [31m-[m
 .../hazmat/primitives/asymmetric/ec.py             |    447 [31m-[m
 .../hazmat/primitives/asymmetric/ed25519.py        |    129 [31m-[m
 .../hazmat/primitives/asymmetric/ed448.py          |    131 [31m-[m
 .../hazmat/primitives/asymmetric/padding.py        |    111 [31m-[m
 .../hazmat/primitives/asymmetric/rsa.py            |    285 [31m-[m
 .../hazmat/primitives/asymmetric/types.py          |    111 [31m-[m
 .../hazmat/primitives/asymmetric/utils.py          |     24 [31m-[m
 .../hazmat/primitives/asymmetric/x25519.py         |    122 [31m-[m
 .../hazmat/primitives/asymmetric/x448.py           |    125 [31m-[m
 .../hazmat/primitives/ciphers/__init__.py          |     27 [31m-[m
 .../ciphers/__pycache__/__init__.cpython-312.pyc   |    Bin [31m631[m -> [32m0[m bytes
 .../ciphers/__pycache__/aead.cpython-312.pyc       |    Bin [31m821[m -> [32m0[m bytes
 .../ciphers/__pycache__/algorithms.cpython-312.pyc |    Bin [31m4897[m -> [32m0[m bytes
 .../ciphers/__pycache__/base.cpython-312.pyc       |    Bin [31m7078[m -> [32m0[m bytes
 .../ciphers/__pycache__/modes.cpython-312.pyc      |    Bin [31m11790[m -> [32m0[m bytes
 .../cryptography/hazmat/primitives/ciphers/aead.py |     23 [31m-[m
 .../hazmat/primitives/ciphers/algorithms.py        |    136 [31m-[m
 .../cryptography/hazmat/primitives/ciphers/base.py |    146 [31m-[m
 .../hazmat/primitives/ciphers/modes.py             |    268 [31m-[m
 .../cryptography/hazmat/primitives/cmac.py         |     10 [31m-[m
 .../hazmat/primitives/constant_time.py             |     14 [31m-[m
 .../cryptography/hazmat/primitives/hashes.py       |    246 [31m-[m
 .../cryptography/hazmat/primitives/hmac.py         |     13 [31m-[m
 .../cryptography/hazmat/primitives/kdf/__init__.py |     23 [31m-[m
 .../kdf/__pycache__/__init__.cpython-312.pyc       |    Bin [31m1239[m -> [32m0[m bytes
 .../kdf/__pycache__/argon2.cpython-312.pyc         |    Bin [31m573[m -> [32m0[m bytes
 .../kdf/__pycache__/concatkdf.cpython-312.pyc      |    Bin [31m5614[m -> [32m0[m bytes
 .../kdf/__pycache__/hkdf.cpython-312.pyc           |    Bin [31m703[m -> [32m0[m bytes
 .../kdf/__pycache__/kbkdf.cpython-312.pyc          |    Bin [31m11288[m -> [32m0[m bytes
 .../kdf/__pycache__/pbkdf2.cpython-312.pyc         |    Bin [31m2718[m -> [32m0[m bytes
 .../kdf/__pycache__/scrypt.cpython-312.pyc         |    Bin [31m659[m -> [32m0[m bytes
 .../kdf/__pycache__/x963kdf.cpython-312.pyc        |    Bin [31m3104[m -> [32m0[m bytes
 .../cryptography/hazmat/primitives/kdf/argon2.py   |     13 [31m-[m
 .../hazmat/primitives/kdf/concatkdf.py             |    125 [31m-[m
 .../cryptography/hazmat/primitives/kdf/hkdf.py     |     16 [31m-[m
 .../cryptography/hazmat/primitives/kdf/kbkdf.py    |    303 [31m-[m
 .../cryptography/hazmat/primitives/kdf/pbkdf2.py   |     62 [31m-[m
 .../cryptography/hazmat/primitives/kdf/scrypt.py   |     19 [31m-[m
 .../cryptography/hazmat/primitives/kdf/x963kdf.py  |     61 [31m-[m
 .../cryptography/hazmat/primitives/keywrap.py      |    177 [31m-[m
 .../cryptography/hazmat/primitives/padding.py      |     69 [31m-[m
 .../cryptography/hazmat/primitives/poly1305.py     |     11 [31m-[m
 .../hazmat/primitives/serialization/__init__.py    |     65 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1371[m -> [32m0[m bytes
 .../serialization/__pycache__/base.cpython-312.pyc |    Bin [31m836[m -> [32m0[m bytes
 .../__pycache__/pkcs12.cpython-312.pyc             |    Bin [31m6620[m -> [32m0[m bytes
 .../__pycache__/pkcs7.cpython-312.pyc              |    Bin [31m17270[m -> [32m0[m bytes
 .../serialization/__pycache__/ssh.cpython-312.pyc  |    Bin [31m67177[m -> [32m0[m bytes
 .../hazmat/primitives/serialization/base.py        |     14 [31m-[m
 .../hazmat/primitives/serialization/pkcs12.py      |    176 [31m-[m
 .../hazmat/primitives/serialization/pkcs7.py       |    411 [31m-[m
 .../hazmat/primitives/serialization/ssh.py         |   1619 [31m-[m
 .../hazmat/primitives/twofactor/__init__.py        |      9 [31m-[m
 .../twofactor/__pycache__/__init__.cpython-312.pyc |    Bin [31m445[m -> [32m0[m bytes
 .../twofactor/__pycache__/hotp.cpython-312.pyc     |    Bin [31m5145[m -> [32m0[m bytes
 .../twofactor/__pycache__/totp.cpython-312.pyc     |    Bin [31m2504[m -> [32m0[m bytes
 .../hazmat/primitives/twofactor/hotp.py            |    101 [31m-[m
 .../hazmat/primitives/twofactor/totp.py            |     56 [31m-[m
 .../venv/Lib/site-packages/cryptography/py.typed   |      0
 .../venv/Lib/site-packages/cryptography/utils.py   |    137 [31m-[m
 .../site-packages/cryptography/x509/__init__.py    |    270 [31m-[m
 .../x509/__pycache__/__init__.cpython-312.pyc      |    Bin [31m8434[m -> [32m0[m bytes
 .../x509/__pycache__/base.cpython-312.pyc          |    Bin [31m33485[m -> [32m0[m bytes
 .../certificate_transparency.cpython-312.pyc       |    Bin [31m1400[m -> [32m0[m bytes
 .../x509/__pycache__/extensions.cpython-312.pyc    |    Bin [31m112578[m -> [32m0[m bytes
 .../x509/__pycache__/general_name.cpython-312.pyc  |    Bin [31m13079[m -> [32m0[m bytes
 .../x509/__pycache__/name.cpython-312.pyc          |    Bin [31m23272[m -> [32m0[m bytes
 .../x509/__pycache__/ocsp.cpython-312.pyc          |    Bin [31m14972[m -> [32m0[m bytes
 .../x509/__pycache__/oid.cpython-312.pyc           |    Bin [31m753[m -> [32m0[m bytes
 .../x509/__pycache__/verification.cpython-312.pyc  |    Bin [31m999[m -> [32m0[m bytes
 .../Lib/site-packages/cryptography/x509/base.py    |    848 [31m-[m
 .../cryptography/x509/certificate_transparency.py  |     35 [31m-[m
 .../site-packages/cryptography/x509/extensions.py  |   2528 [31m-[m
 .../cryptography/x509/general_name.py              |    281 [31m-[m
 .../Lib/site-packages/cryptography/x509/name.py    |    476 [31m-[m
 .../Lib/site-packages/cryptography/x509/ocsp.py    |    379 [31m-[m
 .../Lib/site-packages/cryptography/x509/oid.py     |     37 [31m-[m
 .../cryptography/x509/verification.py              |     34 [31m-[m
 .../venv/Lib/site-packages/dateutil/__init__.py    |     24 [31m-[m
 .../dateutil/__pycache__/__init__.cpython-312.pyc  |    Bin [31m1120[m -> [32m0[m bytes
 .../dateutil/__pycache__/_common.cpython-312.pyc   |    Bin [31m1913[m -> [32m0[m bytes
 .../dateutil/__pycache__/_version.cpython-312.pyc  |    Bin [31m292[m -> [32m0[m bytes
 .../dateutil/__pycache__/easter.cpython-312.pyc    |    Bin [31m2836[m -> [32m0[m bytes
 .../__pycache__/relativedelta.cpython-312.pyc      |    Bin [31m28332[m -> [32m0[m bytes
 .../dateutil/__pycache__/rrule.cpython-312.pyc     |    Bin [31m68913[m -> [32m0[m bytes
 .../dateutil/__pycache__/tzwin.cpython-312.pyc     |    Bin [31m195[m -> [32m0[m bytes
 .../dateutil/__pycache__/utils.cpython-312.pyc     |    Bin [31m2548[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/dateutil/_common.py |     43 [31m-[m
 .../venv/Lib/site-packages/dateutil/_version.py    |      4 [31m-[m
 backend/venv/Lib/site-packages/dateutil/easter.py  |     89 [31m-[m
 .../Lib/site-packages/dateutil/parser/__init__.py  |     61 [31m-[m
 .../parser/__pycache__/__init__.cpython-312.pyc    |    Bin [31m2642[m -> [32m0[m bytes
 .../parser/__pycache__/_parser.cpython-312.pyc     |    Bin [31m61799[m -> [32m0[m bytes
 .../parser/__pycache__/isoparser.cpython-312.pyc   |    Bin [31m15567[m -> [32m0[m bytes
 .../Lib/site-packages/dateutil/parser/_parser.py   |   1613 [31m-[m
 .../Lib/site-packages/dateutil/parser/isoparser.py |    416 [31m-[m
 .../Lib/site-packages/dateutil/relativedelta.py    |    599 [31m-[m
 backend/venv/Lib/site-packages/dateutil/rrule.py   |   1737 [31m-[m
 .../venv/Lib/site-packages/dateutil/tz/__init__.py |     12 [31m-[m
 .../tz/__pycache__/__init__.cpython-312.pyc        |    Bin [31m695[m -> [32m0[m bytes
 .../tz/__pycache__/_common.cpython-312.pyc         |    Bin [31m14138[m -> [32m0[m bytes
 .../tz/__pycache__/_factories.cpython-312.pyc      |    Bin [31m4571[m -> [32m0[m bytes
 .../dateutil/tz/__pycache__/tz.cpython-312.pyc     |    Bin [31m65838[m -> [32m0[m bytes
 .../dateutil/tz/__pycache__/win.cpython-312.pyc    |    Bin [31m17200[m -> [32m0[m bytes
 .../venv/Lib/site-packages/dateutil/tz/_common.py  |    419 [31m-[m
 .../Lib/site-packages/dateutil/tz/_factories.py    |     80 [31m-[m
 backend/venv/Lib/site-packages/dateutil/tz/tz.py   |   1849 [31m-[m
 backend/venv/Lib/site-packages/dateutil/tz/win.py  |    370 [31m-[m
 backend/venv/Lib/site-packages/dateutil/tzwin.py   |      2 [31m-[m
 backend/venv/Lib/site-packages/dateutil/utils.py   |     71 [31m-[m
 .../site-packages/dateutil/zoneinfo/__init__.py    |    167 [31m-[m
 .../zoneinfo/__pycache__/__init__.cpython-312.pyc  |    Bin [31m7417[m -> [32m0[m bytes
 .../zoneinfo/__pycache__/rebuild.cpython-312.pyc   |    Bin [31m3914[m -> [32m0[m bytes
 .../dateutil/zoneinfo/dateutil-zoneinfo.tar.gz     |    Bin [31m156400[m -> [32m0[m bytes
 .../Lib/site-packages/dateutil/zoneinfo/rebuild.py |     75 [31m-[m
 .../site-packages/distro-1.9.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/distro-1.9.0.dist-info/LICENSE   |    202 [31m-[m
 .../site-packages/distro-1.9.0.dist-info/METADATA  |    184 [31m-[m
 .../site-packages/distro-1.9.0.dist-info/RECORD    |     15 [31m-[m
 .../Lib/site-packages/distro-1.9.0.dist-info/WHEEL |      5 [31m-[m
 .../distro-1.9.0.dist-info/entry_points.txt        |      2 [31m-[m
 .../distro-1.9.0.dist-info/top_level.txt           |      1 [31m-[m
 backend/venv/Lib/site-packages/distro/__init__.py  |     54 [31m-[m
 backend/venv/Lib/site-packages/distro/__main__.py  |      4 [31m-[m
 .../distro/__pycache__/__init__.cpython-312.pyc    |    Bin [31m938[m -> [32m0[m bytes
 .../distro/__pycache__/__main__.cpython-312.pyc    |    Bin [31m270[m -> [32m0[m bytes
 .../distro/__pycache__/distro.cpython-312.pyc      |    Bin [31m53770[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/distro/distro.py    |   1403 [31m-[m
 backend/venv/Lib/site-packages/distro/py.typed     |      0
 backend/venv/Lib/site-packages/dns/__init__.py     |     72 [31m-[m
 .../dns/__pycache__/__init__.cpython-312.pyc       |    Bin [31m725[m -> [32m0[m bytes
 .../dns/__pycache__/_asyncbackend.cpython-312.pyc  |    Bin [31m4830[m -> [32m0[m bytes
 .../__pycache__/_asyncio_backend.cpython-312.pyc   |    Bin [31m14324[m -> [32m0[m bytes
 .../dns/__pycache__/_ddr.cpython-312.pyc           |    Bin [31m7783[m -> [32m0[m bytes
 .../dns/__pycache__/_features.cpython-312.pyc      |    Bin [31m3282[m -> [32m0[m bytes
 .../dns/__pycache__/_immutable_ctx.cpython-312.pyc |    Bin [31m3220[m -> [32m0[m bytes
 .../dns/__pycache__/_no_ssl.cpython-312.pyc        |    Bin [31m3141[m -> [32m0[m bytes
 .../dns/__pycache__/_tls_util.cpython-312.pyc      |    Bin [31m878[m -> [32m0[m bytes
 .../dns/__pycache__/_trio_backend.cpython-312.pyc  |    Bin [31m13546[m -> [32m0[m bytes
 .../dns/__pycache__/asyncbackend.cpython-312.pyc   |    Bin [31m3403[m -> [32m0[m bytes
 .../dns/__pycache__/asyncquery.cpython-312.pyc     |    Bin [31m38323[m -> [32m0[m bytes
 .../dns/__pycache__/asyncresolver.cpython-312.pyc  |    Bin [31m21124[m -> [32m0[m bytes
 .../dns/__pycache__/btree.cpython-312.pyc          |    Bin [31m40858[m -> [32m0[m bytes
 .../dns/__pycache__/btreezone.cpython-312.pyc      |    Bin [31m21007[m -> [32m0[m bytes
 .../dns/__pycache__/dnssec.cpython-312.pyc         |    Bin [31m51150[m -> [32m0[m bytes
 .../dns/__pycache__/dnssectypes.cpython-312.pyc    |    Bin [31m1961[m -> [32m0[m bytes
 .../dns/__pycache__/e164.cpython-312.pyc           |    Bin [31m4788[m -> [32m0[m bytes
 .../dns/__pycache__/edns.cpython-312.pyc           |    Bin [31m26101[m -> [32m0[m bytes
 .../dns/__pycache__/entropy.cpython-312.pyc        |    Bin [31m5929[m -> [32m0[m bytes
 .../dns/__pycache__/enum.cpython-312.pyc           |    Bin [31m4856[m -> [32m0[m bytes
 .../dns/__pycache__/exception.cpython-312.pyc      |    Bin [31m7187[m -> [32m0[m bytes
 .../dns/__pycache__/flags.cpython-312.pyc          |    Bin [31m3053[m -> [32m0[m bytes
 .../dns/__pycache__/grange.cpython-312.pyc         |    Bin [31m1771[m -> [32m0[m bytes
 .../dns/__pycache__/immutable.cpython-312.pyc      |    Bin [31m3765[m -> [32m0[m bytes
 .../dns/__pycache__/inet.cpython-312.pyc           |    Bin [31m6655[m -> [32m0[m bytes
 .../dns/__pycache__/ipv4.cpython-312.pyc           |    Bin [31m2549[m -> [32m0[m bytes
 .../dns/__pycache__/ipv6.cpython-312.pyc           |    Bin [31m6664[m -> [32m0[m bytes
 .../dns/__pycache__/message.cpython-312.pyc        |    Bin [31m88642[m -> [32m0[m bytes
 .../dns/__pycache__/name.cpython-312.pyc           |    Bin [31m49108[m -> [32m0[m bytes
 .../dns/__pycache__/namedict.cpython-312.pyc       |    Bin [31m4337[m -> [32m0[m bytes
 .../dns/__pycache__/nameserver.cpython-312.pyc     |    Bin [31m14186[m -> [32m0[m bytes
 .../dns/__pycache__/node.cpython-312.pyc           |    Bin [31m16562[m -> [32m0[m bytes
 .../dns/__pycache__/opcode.cpython-312.pyc         |    Bin [31m3201[m -> [32m0[m bytes
 .../dns/__pycache__/query.cpython-312.pyc          |    Bin [31m69268[m -> [32m0[m bytes
 .../dns/__pycache__/rcode.cpython-312.pyc          |    Bin [31m4477[m -> [32m0[m bytes
 .../dns/__pycache__/rdata.cpython-312.pyc          |    Bin [31m39732[m -> [32m0[m bytes
 .../dns/__pycache__/rdataclass.cpython-312.pyc     |    Bin [31m3509[m -> [32m0[m bytes
 .../dns/__pycache__/rdataset.cpython-312.pyc       |    Bin [31m22895[m -> [32m0[m bytes
 .../dns/__pycache__/rdatatype.cpython-312.pyc      |    Bin [31m10289[m -> [32m0[m bytes
 .../dns/__pycache__/renderer.cpython-312.pyc       |    Bin [31m16223[m -> [32m0[m bytes
 .../dns/__pycache__/resolver.cpython-312.pyc       |    Bin [31m88173[m -> [32m0[m bytes
 .../dns/__pycache__/reversename.cpython-312.pyc    |    Bin [31m4763[m -> [32m0[m bytes
 .../dns/__pycache__/rrset.cpython-312.pyc          |    Bin [31m12445[m -> [32m0[m bytes
 .../dns/__pycache__/serial.cpython-312.pyc         |    Bin [31m5173[m -> [32m0[m bytes
 .../dns/__pycache__/set.cpython-312.pyc            |    Bin [31m12216[m -> [32m0[m bytes
 .../dns/__pycache__/tokenizer.cpython-312.pyc      |    Bin [31m26528[m -> [32m0[m bytes
 .../dns/__pycache__/transaction.cpython-312.pyc    |    Bin [31m29271[m -> [32m0[m bytes
 .../dns/__pycache__/tsig.cpython-312.pyc           |    Bin [31m17008[m -> [32m0[m bytes
 .../dns/__pycache__/tsigkeyring.cpython-312.pyc    |    Bin [31m2829[m -> [32m0[m bytes
 .../dns/__pycache__/ttl.cpython-312.pyc            |    Bin [31m2329[m -> [32m0[m bytes
 .../dns/__pycache__/update.cpython-312.pyc         |    Bin [31m16210[m -> [32m0[m bytes
 .../dns/__pycache__/version.cpython-312.pyc        |    Bin [31m754[m -> [32m0[m bytes
 .../dns/__pycache__/versioned.cpython-312.pyc      |    Bin [31m14729[m -> [32m0[m bytes
 .../dns/__pycache__/win32util.cpython-312.pyc      |    Bin [31m19763[m -> [32m0[m bytes
 .../dns/__pycache__/wire.cpython-312.pyc           |    Bin [31m5766[m -> [32m0[m bytes
 .../dns/__pycache__/xfr.cpython-312.pyc            |    Bin [31m15018[m -> [32m0[m bytes
 .../dns/__pycache__/zone.cpython-312.pyc           |    Bin [31m68491[m -> [32m0[m bytes
 .../dns/__pycache__/zonefile.cpython-312.pyc       |    Bin [31m34481[m -> [32m0[m bytes
 .../dns/__pycache__/zonetypes.cpython-312.pyc      |    Bin [31m1335[m -> [32m0[m bytes
 .../venv/Lib/site-packages/dns/_asyncbackend.py    |    100 [31m-[m
 .../venv/Lib/site-packages/dns/_asyncio_backend.py |    276 [31m-[m
 backend/venv/Lib/site-packages/dns/_ddr.py         |    154 [31m-[m
 backend/venv/Lib/site-packages/dns/_features.py    |     95 [31m-[m
 .../venv/Lib/site-packages/dns/_immutable_ctx.py   |     76 [31m-[m
 backend/venv/Lib/site-packages/dns/_no_ssl.py      |     61 [31m-[m
 backend/venv/Lib/site-packages/dns/_tls_util.py    |     19 [31m-[m
 .../venv/Lib/site-packages/dns/_trio_backend.py    |    255 [31m-[m
 backend/venv/Lib/site-packages/dns/asyncbackend.py |    101 [31m-[m
 backend/venv/Lib/site-packages/dns/asyncquery.py   |    953 [31m-[m
 .../venv/Lib/site-packages/dns/asyncresolver.py    |    478 [31m-[m
 backend/venv/Lib/site-packages/dns/btree.py        |    850 [31m-[m
 backend/venv/Lib/site-packages/dns/btreezone.py    |    367 [31m-[m
 backend/venv/Lib/site-packages/dns/dnssec.py       |   1242 [31m-[m
 .../Lib/site-packages/dns/dnssecalgs/__init__.py   |    124 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m5474[m -> [32m0[m bytes
 .../dnssecalgs/__pycache__/base.cpython-312.pyc    |    Bin [31m4579[m -> [32m0[m bytes
 .../__pycache__/cryptography.cpython-312.pyc       |    Bin [31m3789[m -> [32m0[m bytes
 .../dns/dnssecalgs/__pycache__/dsa.cpython-312.pyc |    Bin [31m6218[m -> [32m0[m bytes
 .../dnssecalgs/__pycache__/ecdsa.cpython-312.pyc   |    Bin [31m6083[m -> [32m0[m bytes
 .../dnssecalgs/__pycache__/eddsa.cpython-312.pyc   |    Bin [31m4188[m -> [32m0[m bytes
 .../dns/dnssecalgs/__pycache__/rsa.cpython-312.pyc |    Bin [31m7249[m -> [32m0[m bytes
 .../venv/Lib/site-packages/dns/dnssecalgs/base.py  |     89 [31m-[m
 .../site-packages/dns/dnssecalgs/cryptography.py   |     68 [31m-[m
 .../venv/Lib/site-packages/dns/dnssecalgs/dsa.py   |    108 [31m-[m
 .../venv/Lib/site-packages/dns/dnssecalgs/ecdsa.py |    100 [31m-[m
 .../venv/Lib/site-packages/dns/dnssecalgs/eddsa.py |     70 [31m-[m
 .../venv/Lib/site-packages/dns/dnssecalgs/rsa.py   |    126 [31m-[m
 backend/venv/Lib/site-packages/dns/dnssectypes.py  |     71 [31m-[m
 backend/venv/Lib/site-packages/dns/e164.py         |    116 [31m-[m
 backend/venv/Lib/site-packages/dns/edns.py         |    591 [31m-[m
 backend/venv/Lib/site-packages/dns/entropy.py      |    130 [31m-[m
 backend/venv/Lib/site-packages/dns/enum.py         |    113 [31m-[m
 backend/venv/Lib/site-packages/dns/exception.py    |    169 [31m-[m
 backend/venv/Lib/site-packages/dns/flags.py        |    123 [31m-[m
 backend/venv/Lib/site-packages/dns/grange.py       |     72 [31m-[m
 backend/venv/Lib/site-packages/dns/immutable.py    |     68 [31m-[m
 backend/venv/Lib/site-packages/dns/inet.py         |    195 [31m-[m
 backend/venv/Lib/site-packages/dns/ipv4.py         |     76 [31m-[m
 backend/venv/Lib/site-packages/dns/ipv6.py         |    217 [31m-[m
 backend/venv/Lib/site-packages/dns/message.py      |   1954 [31m-[m
 backend/venv/Lib/site-packages/dns/name.py         |   1289 [31m-[m
 backend/venv/Lib/site-packages/dns/namedict.py     |    109 [31m-[m
 backend/venv/Lib/site-packages/dns/nameserver.py   |    361 [31m-[m
 backend/venv/Lib/site-packages/dns/node.py         |    358 [31m-[m
 backend/venv/Lib/site-packages/dns/opcode.py       |    119 [31m-[m
 backend/venv/Lib/site-packages/dns/py.typed        |      0
 backend/venv/Lib/site-packages/dns/query.py        |   1786 [31m-[m
 .../venv/Lib/site-packages/dns/quic/__init__.py    |     78 [31m-[m
 .../dns/quic/__pycache__/__init__.cpython-312.pyc  |    Bin [31m3293[m -> [32m0[m bytes
 .../dns/quic/__pycache__/_asyncio.cpython-312.pyc  |    Bin [31m18718[m -> [32m0[m bytes
 .../dns/quic/__pycache__/_common.cpython-312.pyc   |    Bin [31m15031[m -> [32m0[m bytes
 .../dns/quic/__pycache__/_sync.cpython-312.pyc     |    Bin [31m19431[m -> [32m0[m bytes
 .../dns/quic/__pycache__/_trio.cpython-312.pyc     |    Bin [31m15974[m -> [32m0[m bytes
 .../venv/Lib/site-packages/dns/quic/_asyncio.py    |    276 [31m-[m
 backend/venv/Lib/site-packages/dns/quic/_common.py |    344 [31m-[m
 backend/venv/Lib/site-packages/dns/quic/_sync.py   |    306 [31m-[m
 backend/venv/Lib/site-packages/dns/quic/_trio.py   |    250 [31m-[m
 backend/venv/Lib/site-packages/dns/rcode.py        |    168 [31m-[m
 backend/venv/Lib/site-packages/dns/rdata.py        |    935 [31m-[m
 backend/venv/Lib/site-packages/dns/rdataclass.py   |    118 [31m-[m
 backend/venv/Lib/site-packages/dns/rdataset.py     |    508 [31m-[m
 backend/venv/Lib/site-packages/dns/rdatatype.py    |    338 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/AFSDB.py     |     45 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/AMTRELAY.py  |     89 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/AVC.py  |     26 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/CAA.py  |     67 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/CDNSKEY.py   |     33 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/CDS.py  |     29 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/CERT.py |    113 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/CNAME.py     |     28 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/CSYNC.py     |     68 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/DLV.py  |     24 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/DNAME.py     |     27 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/DNSKEY.py    |     33 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/DS.py   |     24 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/DSYNC.py     |     72 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/EUI48.py     |     30 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/EUI64.py     |     30 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/GPOS.py |    126 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/HINFO.py     |     64 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/HIP.py  |     85 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/ISDN.py |     78 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/L32.py  |     42 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/L64.py  |     48 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/LOC.py  |    347 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/LP.py   |     42 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/MX.py   |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/NID.py  |     48 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/NINFO.py     |     26 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/NS.py   |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/NSEC.py |     67 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/NSEC3.py     |    120 [31m-[m
 .../site-packages/dns/rdtypes/ANY/NSEC3PARAM.py    |     69 [31m-[m
 .../site-packages/dns/rdtypes/ANY/OPENPGPKEY.py    |     53 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/OPT.py  |     77 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/PTR.py  |     24 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/RESINFO.py   |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/RP.py   |     58 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/RRSIG.py     |    155 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/RT.py   |     24 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/SMIMEA.py    |      9 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/SOA.py  |     78 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/SPF.py  |     26 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/SSHFP.py     |     67 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/TKEY.py |    135 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/TLSA.py |      9 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/TSIG.py |    160 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/TXT.py  |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/URI.py  |     79 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/WALLET.py    |      9 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/ANY/X25.py  |     57 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/ZONEMD.py    |     64 [31m-[m
 .../Lib/site-packages/dns/rdtypes/ANY/__init__.py  |     71 [31m-[m
 .../rdtypes/ANY/__pycache__/AFSDB.cpython-312.pyc  |    Bin [31m1052[m -> [32m0[m bytes
 .../ANY/__pycache__/AMTRELAY.cpython-312.pyc       |    Bin [31m4203[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/AVC.cpython-312.pyc    |    Bin [31m625[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/CAA.cpython-312.pyc    |    Bin [31m3361[m -> [32m0[m bytes
 .../ANY/__pycache__/CDNSKEY.cpython-312.pyc        |    Bin [31m712[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/CDS.cpython-312.pyc    |    Bin [31m820[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/CERT.cpython-312.pyc   |    Bin [31m4469[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/CNAME.cpython-312.pyc  |    Bin [31m835[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/CSYNC.cpython-312.pyc  |    Bin [31m3320[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/DLV.cpython-312.pyc    |    Bin [31m622[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/DNAME.cpython-312.pyc  |    Bin [31m898[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/DNSKEY.cpython-312.pyc |    Bin [31m709[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/DS.cpython-312.pyc |    Bin [31m619[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/DSYNC.cpython-312.pyc  |    Bin [31m4295[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/EUI48.cpython-312.pyc  |    Bin [31m707[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/EUI64.cpython-312.pyc  |    Bin [31m707[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/GPOS.cpython-312.pyc   |    Bin [31m6089[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/HINFO.cpython-312.pyc  |    Bin [31m2954[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/HIP.cpython-312.pyc    |    Bin [31m4804[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/ISDN.cpython-312.pyc   |    Bin [31m3421[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/L32.cpython-312.pyc    |    Bin [31m2508[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/L64.cpython-312.pyc    |    Bin [31m2966[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/LOC.cpython-312.pyc    |    Bin [31m14111[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/LP.cpython-312.pyc |    Bin [31m2457[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/MX.cpython-312.pyc |    Bin [31m619[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/NID.cpython-312.pyc    |    Bin [31m2959[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/NINFO.cpython-312.pyc  |    Bin [31m631[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/NS.cpython-312.pyc |    Bin [31m619[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/NSEC.cpython-312.pyc   |    Bin [31m3063[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/NSEC3.cpython-312.pyc  |    Bin [31m6367[m -> [32m0[m bytes
 .../ANY/__pycache__/NSEC3PARAM.cpython-312.pyc     |    Bin [31m3382[m -> [32m0[m bytes
 .../ANY/__pycache__/OPENPGPKEY.cpython-312.pyc     |    Bin [31m2297[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/OPT.cpython-312.pyc    |    Bin [31m3496[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/PTR.cpython-312.pyc    |    Bin [31m622[m -> [32m0[m bytes
 .../ANY/__pycache__/RESINFO.cpython-312.pyc        |    Bin [31m637[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/RP.cpython-312.pyc |    Bin [31m2517[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/RRSIG.cpython-312.pyc  |    Bin [31m6584[m -> [32m0[m bytes
 .../dns/rdtypes/ANY/__pycache__/RT.cpython-312.pyc |    Bin [31m637[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/SMIMEA.cpython-312.pyc |    Bin [31m637[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/SOA.cpython-312.pyc    |    Bin [31m3794[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/SPF.cpython-312.pyc    |    Bin [31m625[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/SSHFP.cpython-312.pyc  |    Bin [31m3127[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/TKEY.cpython-312.pyc   |    Bin [31m5071[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/TLSA.cpython-312.pyc   |    Bin [31m631[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/TSIG.cpython-312.pyc   |    Bin [31m5891[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/TXT.cpython-312.pyc    |    Bin [31m625[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/URI.cpython-312.pyc    |    Bin [31m4150[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/WALLET.cpython-312.pyc |    Bin [31m634[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/X25.cpython-312.pyc    |    Bin [31m2339[m -> [32m0[m bytes
 .../rdtypes/ANY/__pycache__/ZONEMD.cpython-312.pyc |    Bin [31m4180[m -> [32m0[m bytes
 .../ANY/__pycache__/__init__.cpython-312.pyc       |    Bin [31m573[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/dns/rdtypes/CH/A.py |     60 [31m-[m
 .../Lib/site-packages/dns/rdtypes/CH/__init__.py   |     22 [31m-[m
 .../dns/rdtypes/CH/__pycache__/A.cpython-312.pyc   |    Bin [31m2532[m -> [32m0[m bytes
 .../CH/__pycache__/__init__.cpython-312.pyc        |    Bin [31m251[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/dns/rdtypes/IN/A.py |     51 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/AAAA.py  |     51 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/APL.py   |    150 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/DHCID.py |     54 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/HTTPS.py |      9 [31m-[m
 .../Lib/site-packages/dns/rdtypes/IN/IPSECKEY.py   |     87 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/KX.py    |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/NAPTR.py |    109 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/NSAP.py  |     60 [31m-[m
 .../Lib/site-packages/dns/rdtypes/IN/NSAP_PTR.py   |     24 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/PX.py    |     73 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/SRV.py   |     75 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/SVCB.py  |      9 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/IN/WKS.py   |    100 [31m-[m
 .../Lib/site-packages/dns/rdtypes/IN/__init__.py   |     35 [31m-[m
 .../dns/rdtypes/IN/__pycache__/A.cpython-312.pyc   |    Bin [31m2099[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/AAAA.cpython-312.pyc    |    Bin [31m2123[m -> [32m0[m bytes
 .../dns/rdtypes/IN/__pycache__/APL.cpython-312.pyc |    Bin [31m6889[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/DHCID.cpython-312.pyc   |    Bin [31m2243[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/HTTPS.cpython-312.pyc   |    Bin [31m633[m -> [32m0[m bytes
 .../IN/__pycache__/IPSECKEY.cpython-312.pyc        |    Bin [31m4231[m -> [32m0[m bytes
 .../dns/rdtypes/IN/__pycache__/KX.cpython-312.pyc  |    Bin [31m636[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/NAPTR.cpython-312.pyc   |    Bin [31m5040[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/NSAP.cpython-312.pyc    |    Bin [31m2689[m -> [32m0[m bytes
 .../IN/__pycache__/NSAP_PTR.cpython-312.pyc        |    Bin [31m644[m -> [32m0[m bytes
 .../dns/rdtypes/IN/__pycache__/PX.cpython-312.pyc  |    Bin [31m3439[m -> [32m0[m bytes
 .../dns/rdtypes/IN/__pycache__/SRV.cpython-312.pyc |    Bin [31m3692[m -> [32m0[m bytes
 .../rdtypes/IN/__pycache__/SVCB.cpython-312.pyc    |    Bin [31m630[m -> [32m0[m bytes
 .../dns/rdtypes/IN/__pycache__/WKS.cpython-312.pyc |    Bin [31m4573[m -> [32m0[m bytes
 .../IN/__pycache__/__init__.cpython-312.pyc        |    Bin [31m332[m -> [32m0[m bytes
 .../venv/Lib/site-packages/dns/rdtypes/__init__.py |     33 [31m-[m
 .../rdtypes/__pycache__/__init__.cpython-312.pyc   |    Bin [31m331[m -> [32m0[m bytes
 .../rdtypes/__pycache__/dnskeybase.cpython-312.pyc |    Bin [31m3869[m -> [32m0[m bytes
 .../dns/rdtypes/__pycache__/dsbase.cpython-312.pyc |    Bin [31m4180[m -> [32m0[m bytes
 .../rdtypes/__pycache__/euibase.cpython-312.pyc    |    Bin [31m3583[m -> [32m0[m bytes
 .../dns/rdtypes/__pycache__/mxbase.cpython-312.pyc |    Bin [31m4383[m -> [32m0[m bytes
 .../dns/rdtypes/__pycache__/nsbase.cpython-312.pyc |    Bin [31m2816[m -> [32m0[m bytes
 .../rdtypes/__pycache__/svcbbase.cpython-312.pyc   |    Bin [31m29817[m -> [32m0[m bytes
 .../rdtypes/__pycache__/tlsabase.cpython-312.pyc   |    Bin [31m3376[m -> [32m0[m bytes
 .../rdtypes/__pycache__/txtbase.cpython-312.pyc    |    Bin [31m5151[m -> [32m0[m bytes
 .../dns/rdtypes/__pycache__/util.cpython-312.pyc   |    Bin [31m13797[m -> [32m0[m bytes
 .../Lib/site-packages/dns/rdtypes/dnskeybase.py    |     83 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/dsbase.py   |     83 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/euibase.py  |     73 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/mxbase.py   |     87 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/nsbase.py   |     63 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/svcbbase.py |    587 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/tlsabase.py |     69 [31m-[m
 .../venv/Lib/site-packages/dns/rdtypes/txtbase.py  |    109 [31m-[m
 backend/venv/Lib/site-packages/dns/rdtypes/util.py |    269 [31m-[m
 backend/venv/Lib/site-packages/dns/renderer.py     |    355 [31m-[m
 backend/venv/Lib/site-packages/dns/resolver.py     |   2068 [31m-[m
 backend/venv/Lib/site-packages/dns/reversename.py  |    106 [31m-[m
 backend/venv/Lib/site-packages/dns/rrset.py        |    287 [31m-[m
 backend/venv/Lib/site-packages/dns/serial.py       |    118 [31m-[m
 backend/venv/Lib/site-packages/dns/set.py          |    308 [31m-[m
 backend/venv/Lib/site-packages/dns/tokenizer.py    |    706 [31m-[m
 backend/venv/Lib/site-packages/dns/transaction.py  |    651 [31m-[m
 backend/venv/Lib/site-packages/dns/tsig.py         |    359 [31m-[m
 backend/venv/Lib/site-packages/dns/tsigkeyring.py  |     68 [31m-[m
 backend/venv/Lib/site-packages/dns/ttl.py          |     90 [31m-[m
 backend/venv/Lib/site-packages/dns/update.py       |    389 [31m-[m
 backend/venv/Lib/site-packages/dns/version.py      |     42 [31m-[m
 backend/venv/Lib/site-packages/dns/versioned.py    |    320 [31m-[m
 backend/venv/Lib/site-packages/dns/win32util.py    |    438 [31m-[m
 backend/venv/Lib/site-packages/dns/wire.py         |     98 [31m-[m
 backend/venv/Lib/site-packages/dns/xfr.py          |    356 [31m-[m
 backend/venv/Lib/site-packages/dns/zone.py         |   1462 [31m-[m
 backend/venv/Lib/site-packages/dns/zonefile.py     |    756 [31m-[m
 backend/venv/Lib/site-packages/dns/zonetypes.py    |     37 [31m-[m
 .../dnspython-2.8.0.dist-info/INSTALLER            |      1 [31m-[m
 .../dnspython-2.8.0.dist-info/METADATA             |    149 [31m-[m
 .../site-packages/dnspython-2.8.0.dist-info/RECORD |    304 [31m-[m
 .../site-packages/dnspython-2.8.0.dist-info/WHEEL  |      4 [31m-[m
 .../dnspython-2.8.0.dist-info/licenses/LICENSE     |     35 [31m-[m
 backend/venv/Lib/site-packages/dotenv/__init__.py  |     51 [31m-[m
 backend/venv/Lib/site-packages/dotenv/__main__.py  |      6 [31m-[m
 .../dotenv/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1673[m -> [32m0[m bytes
 .../dotenv/__pycache__/__main__.cpython-312.pyc    |    Bin [31m341[m -> [32m0[m bytes
 .../dotenv/__pycache__/cli.cpython-312.pyc         |    Bin [31m10267[m -> [32m0[m bytes
 .../dotenv/__pycache__/ipython.cpython-312.pyc     |    Bin [31m1957[m -> [32m0[m bytes
 .../dotenv/__pycache__/main.cpython-312.pyc        |    Bin [31m18117[m -> [32m0[m bytes
 .../dotenv/__pycache__/parser.cpython-312.pyc      |    Bin [31m9967[m -> [32m0[m bytes
 .../dotenv/__pycache__/variables.cpython-312.pyc   |    Bin [31m5009[m -> [32m0[m bytes
 .../dotenv/__pycache__/version.cpython-312.pyc     |    Bin [31m193[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/dotenv/cli.py       |    218 [31m-[m
 backend/venv/Lib/site-packages/dotenv/ipython.py   |     50 [31m-[m
 backend/venv/Lib/site-packages/dotenv/main.py      |    435 [31m-[m
 backend/venv/Lib/site-packages/dotenv/parser.py    |    182 [31m-[m
 backend/venv/Lib/site-packages/dotenv/py.typed     |      1 [31m-[m
 backend/venv/Lib/site-packages/dotenv/variables.py |     86 [31m-[m
 backend/venv/Lib/site-packages/dotenv/version.py   |      1 [31m-[m
 .../site-packages/ecdsa-0.19.1.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/ecdsa-0.19.1.dist-info/LICENSE   |     24 [31m-[m
 .../site-packages/ecdsa-0.19.1.dist-info/METADATA  |    671 [31m-[m
 .../site-packages/ecdsa-0.19.1.dist-info/RECORD    |     66 [31m-[m
 .../Lib/site-packages/ecdsa-0.19.1.dist-info/WHEEL |      6 [31m-[m
 .../ecdsa-0.19.1.dist-info/top_level.txt           |      1 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/__init__.py   |    104 [31m-[m
 .../ecdsa/__pycache__/__init__.cpython-312.pyc     |    Bin [31m2043[m -> [32m0[m bytes
 .../ecdsa/__pycache__/_compat.cpython-312.pyc      |    Bin [31m6047[m -> [32m0[m bytes
 .../ecdsa/__pycache__/_rwlock.cpython-312.pyc      |    Bin [31m4820[m -> [32m0[m bytes
 .../ecdsa/__pycache__/_sha3.cpython-312.pyc        |    Bin [31m5066[m -> [32m0[m bytes
 .../ecdsa/__pycache__/_version.cpython-312.pyc     |    Bin [31m556[m -> [32m0[m bytes
 .../ecdsa/__pycache__/curves.cpython-312.pyc       |    Bin [31m18531[m -> [32m0[m bytes
 .../ecdsa/__pycache__/der.cpython-312.pyc          |    Bin [31m19176[m -> [32m0[m bytes
 .../ecdsa/__pycache__/ecdh.cpython-312.pyc         |    Bin [31m13502[m -> [32m0[m bytes
 .../ecdsa/__pycache__/ecdsa.cpython-312.pyc        |    Bin [31m31426[m -> [32m0[m bytes
 .../ecdsa/__pycache__/eddsa.cpython-312.pyc        |    Bin [31m10764[m -> [32m0[m bytes
 .../__pycache__/ellipticcurve.cpython-312.pyc      |    Bin [31m63466[m -> [32m0[m bytes
 .../ecdsa/__pycache__/errors.cpython-312.pyc       |    Bin [31m450[m -> [32m0[m bytes
 .../ecdsa/__pycache__/keys.cpython-312.pyc         |    Bin [31m68096[m -> [32m0[m bytes
 .../ecdsa/__pycache__/numbertheory.cpython-312.pyc |    Bin [31m16983[m -> [32m0[m bytes
 .../ecdsa/__pycache__/rfc6979.cpython-312.pyc      |    Bin [31m3763[m -> [32m0[m bytes
 .../ecdsa/__pycache__/ssh.cpython-312.pyc          |    Bin [31m4308[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_curves.cpython-312.pyc  |    Bin [31m21888[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_der.cpython-312.pyc     |    Bin [31m37304[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_ecdh.cpython-312.pyc    |    Bin [31m20975[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_ecdsa.cpython-312.pyc   |    Bin [31m29529[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_eddsa.cpython-312.pyc   |    Bin [31m42482[m -> [32m0[m bytes
 .../__pycache__/test_ellipticcurve.cpython-312.pyc |    Bin [31m16975[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_jacobi.cpython-312.pyc  |    Bin [31m46632[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_keys.cpython-312.pyc    |    Bin [31m56340[m -> [32m0[m bytes
 .../test_malformed_sigs.cpython-312.pyc            |    Bin [31m15034[m -> [32m0[m bytes
 .../__pycache__/test_numbertheory.cpython-312.pyc  |    Bin [31m21129[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_pyecdsa.cpython-312.pyc |    Bin [31m125870[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_rw_lock.cpython-312.pyc |    Bin [31m10767[m -> [32m0[m bytes
 .../ecdsa/__pycache__/test_sha3.cpython-312.pyc    |    Bin [31m4641[m -> [32m0[m bytes
 .../ecdsa/__pycache__/util.cpython-312.pyc         |    Bin [31m20478[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/ecdsa/_compat.py    |    138 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/_rwlock.py    |     86 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/_sha3.py      |    181 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/_version.py   |     21 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/curves.py     |    590 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/der.py        |    478 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/ecdh.py       |    336 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/ecdsa.py      |   1094 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/eddsa.py      |    252 [31m-[m
 .../venv/Lib/site-packages/ecdsa/ellipticcurve.py  |   1609 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/errors.py     |      4 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/keys.py       |   1631 [31m-[m
 .../venv/Lib/site-packages/ecdsa/numbertheory.py   |    835 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/rfc6979.py    |    113 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/ssh.py        |     83 [31m-[m
 .../venv/Lib/site-packages/ecdsa/test_curves.py    |    361 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_der.py   |    602 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_ecdh.py  |    449 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_ecdsa.py |    694 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_eddsa.py |   1124 [31m-[m
 .../Lib/site-packages/ecdsa/test_ellipticcurve.py  |    294 [31m-[m
 .../venv/Lib/site-packages/ecdsa/test_jacobi.py    |    934 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_keys.py  |   1138 [31m-[m
 .../Lib/site-packages/ecdsa/test_malformed_sigs.py |    378 [31m-[m
 .../Lib/site-packages/ecdsa/test_numbertheory.py   |    483 [31m-[m
 .../venv/Lib/site-packages/ecdsa/test_pyecdsa.py   |   2564 [31m-[m
 .../venv/Lib/site-packages/ecdsa/test_rw_lock.py   |    180 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/test_sha3.py  |    111 [31m-[m
 backend/venv/Lib/site-packages/ecdsa/util.py       |    533 [31m-[m
 .../email_validator-2.3.0.dist-info/INSTALLER      |      1 [31m-[m
 .../email_validator-2.3.0.dist-info/METADATA       |    466 [31m-[m
 .../email_validator-2.3.0.dist-info/RECORD         |     28 [31m-[m
 .../email_validator-2.3.0.dist-info/REQUESTED      |      0
 .../email_validator-2.3.0.dist-info/WHEEL          |      5 [31m-[m
 .../entry_points.txt                               |      2 [31m-[m
 .../licenses/LICENSE                               |     27 [31m-[m
 .../email_validator-2.3.0.dist-info/top_level.txt  |      1 [31m-[m
 .../Lib/site-packages/email_validator/__init__.py  |    103 [31m-[m
 .../Lib/site-packages/email_validator/__main__.py  |     61 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1156[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m2256[m -> [32m0[m bytes
 .../__pycache__/deliverability.cpython-312.pyc     |    Bin [31m5960[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m961[m -> [32m0[m bytes
 .../__pycache__/rfc_constants.cpython-312.pyc      |    Bin [31m1658[m -> [32m0[m bytes
 .../__pycache__/syntax.cpython-312.pyc             |    Bin [31m22924[m -> [32m0[m bytes
 .../__pycache__/types.cpython-312.pyc              |    Bin [31m5540[m -> [32m0[m bytes
 .../__pycache__/validate_email.cpython-312.pyc     |    Bin [31m6200[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m202[m -> [32m0[m bytes
 .../email_validator/deliverability.py              |    159 [31m-[m
 .../site-packages/email_validator/exceptions.py    |     13 [31m-[m
 .../Lib/site-packages/email_validator/py.typed     |      0
 .../site-packages/email_validator/rfc_constants.py |     63 [31m-[m
 .../Lib/site-packages/email_validator/syntax.py    |    822 [31m-[m
 .../Lib/site-packages/email_validator/types.py     |    126 [31m-[m
 .../email_validator/validate_email.py              |    209 [31m-[m
 .../Lib/site-packages/email_validator/version.py   |      1 [31m-[m
 .../fastapi-0.127.0.dist-info/INSTALLER            |      1 [31m-[m
 .../fastapi-0.127.0.dist-info/METADATA             |    639 [31m-[m
 .../site-packages/fastapi-0.127.0.dist-info/RECORD |    113 [31m-[m
 .../fastapi-0.127.0.dist-info/REQUESTED            |      0
 .../site-packages/fastapi-0.127.0.dist-info/WHEEL  |      4 [31m-[m
 .../fastapi-0.127.0.dist-info/entry_points.txt     |      5 [31m-[m
 .../fastapi-0.127.0.dist-info/licenses/LICENSE     |     21 [31m-[m
 backend/venv/Lib/site-packages/fastapi/__init__.py |     25 [31m-[m
 backend/venv/Lib/site-packages/fastapi/__main__.py |      3 [31m-[m
 .../fastapi/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1084[m -> [32m0[m bytes
 .../fastapi/__pycache__/__main__.cpython-312.pyc   |    Bin [31m231[m -> [32m0[m bytes
 .../__pycache__/applications.cpython-312.pyc       |    Bin [31m86641[m -> [32m0[m bytes
 .../fastapi/__pycache__/background.cpython-312.pyc |    Bin [31m2385[m -> [32m0[m bytes
 .../fastapi/__pycache__/cli.cpython-312.pyc        |    Bin [31m645[m -> [32m0[m bytes
 .../__pycache__/concurrency.cpython-312.pyc        |    Bin [31m1706[m -> [32m0[m bytes
 .../__pycache__/datastructures.cpython-312.pyc     |    Bin [31m7135[m -> [32m0[m bytes
 .../fastapi/__pycache__/encoders.cpython-312.pyc   |    Bin [31m11277[m -> [32m0[m bytes
 .../__pycache__/exception_handlers.cpython-312.pyc |    Bin [31m2011[m -> [32m0[m bytes
 .../fastapi/__pycache__/exceptions.cpython-312.pyc |    Bin [31m9387[m -> [32m0[m bytes
 .../fastapi/__pycache__/logger.cpython-312.pyc     |    Bin [31m271[m -> [32m0[m bytes
 .../__pycache__/param_functions.cpython-312.pyc    |    Bin [31m36236[m -> [32m0[m bytes
 .../fastapi/__pycache__/params.cpython-312.pyc     |    Bin [31m24110[m -> [32m0[m bytes
 .../fastapi/__pycache__/requests.cpython-312.pyc   |    Bin [31m260[m -> [32m0[m bytes
 .../fastapi/__pycache__/responses.cpython-312.pyc  |    Bin [31m2388[m -> [32m0[m bytes
 .../fastapi/__pycache__/routing.cpython-312.pyc    |    Bin [31m88129[m -> [32m0[m bytes
 .../__pycache__/staticfiles.cpython-312.pyc        |    Bin [31m232[m -> [32m0[m bytes
 .../temp_pydantic_v1_params.cpython-312.pyc        |    Bin [31m22679[m -> [32m0[m bytes
 .../fastapi/__pycache__/templating.cpython-312.pyc |    Bin [31m234[m -> [32m0[m bytes
 .../fastapi/__pycache__/testclient.cpython-312.pyc |    Bin [31m229[m -> [32m0[m bytes
 .../fastapi/__pycache__/types.cpython-312.pyc      |    Bin [31m838[m -> [32m0[m bytes
 .../fastapi/__pycache__/utils.cpython-312.pyc      |    Bin [31m9085[m -> [32m0[m bytes
 .../fastapi/__pycache__/websockets.cpython-312.pyc |    Bin [31m309[m -> [32m0[m bytes
 .../Lib/site-packages/fastapi/_compat/__init__.py  |     49 [31m-[m
 .../_compat/__pycache__/__init__.cpython-312.pyc   |    Bin [31m2065[m -> [32m0[m bytes
 .../_compat/__pycache__/main.cpython-312.pyc       |    Bin [31m10405[m -> [32m0[m bytes
 .../_compat/__pycache__/may_v1.cpython-312.pyc     |    Bin [31m5058[m -> [32m0[m bytes
 .../__pycache__/model_field.cpython-312.pyc        |    Bin [31m2505[m -> [32m0[m bytes
 .../_compat/__pycache__/shared.cpython-312.pyc     |    Bin [31m8590[m -> [32m0[m bytes
 .../fastapi/_compat/__pycache__/v1.cpython-312.pyc |    Bin [31m8985[m -> [32m0[m bytes
 .../fastapi/_compat/__pycache__/v2.cpython-312.pyc |    Bin [31m23125[m -> [32m0[m bytes
 .../venv/Lib/site-packages/fastapi/_compat/main.py |    264 [31m-[m
 .../Lib/site-packages/fastapi/_compat/may_v1.py    |    124 [31m-[m
 .../site-packages/fastapi/_compat/model_field.py   |     50 [31m-[m
 .../Lib/site-packages/fastapi/_compat/shared.py    |    194 [31m-[m
 .../venv/Lib/site-packages/fastapi/_compat/v1.py   |    222 [31m-[m
 .../venv/Lib/site-packages/fastapi/_compat/v2.py   |    571 [31m-[m
 .../venv/Lib/site-packages/fastapi/applications.py |   4669 [31m-[m
 .../venv/Lib/site-packages/fastapi/background.py   |     60 [31m-[m
 backend/venv/Lib/site-packages/fastapi/cli.py      |     13 [31m-[m
 .../venv/Lib/site-packages/fastapi/concurrency.py  |     41 [31m-[m
 .../Lib/site-packages/fastapi/datastructures.py    |    186 [31m-[m
 .../site-packages/fastapi/dependencies/__init__.py |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m182[m -> [32m0[m bytes
 .../__pycache__/models.cpython-312.pyc             |    Bin [31m9199[m -> [32m0[m bytes
 .../dependencies/__pycache__/utils.cpython-312.pyc |    Bin [31m42490[m -> [32m0[m bytes
 .../site-packages/fastapi/dependencies/models.py   |    193 [31m-[m
 .../site-packages/fastapi/dependencies/utils.py    |   1069 [31m-[m
 backend/venv/Lib/site-packages/fastapi/encoders.py |    355 [31m-[m
 .../site-packages/fastapi/exception_handlers.py    |     34 [31m-[m
 .../venv/Lib/site-packages/fastapi/exceptions.py   |    233 [31m-[m
 backend/venv/Lib/site-packages/fastapi/logger.py   |      3 [31m-[m
 .../site-packages/fastapi/middleware/__init__.py   |      1 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m238[m -> [32m0[m bytes
 .../__pycache__/asyncexitstack.cpython-312.pyc     |    Bin [31m1473[m -> [32m0[m bytes
 .../middleware/__pycache__/cors.cpython-312.pyc    |    Bin [31m243[m -> [32m0[m bytes
 .../middleware/__pycache__/gzip.cpython-312.pyc    |    Bin [31m243[m -> [32m0[m bytes
 .../__pycache__/httpsredirect.cpython-312.pyc      |    Bin [31m272[m -> [32m0[m bytes
 .../__pycache__/trustedhost.cpython-312.pyc        |    Bin [31m266[m -> [32m0[m bytes
 .../middleware/__pycache__/wsgi.cpython-312.pyc    |    Bin [31m243[m -> [32m0[m bytes
 .../fastapi/middleware/asyncexitstack.py           |     18 [31m-[m
 .../Lib/site-packages/fastapi/middleware/cors.py   |      1 [31m-[m
 .../Lib/site-packages/fastapi/middleware/gzip.py   |      1 [31m-[m
 .../fastapi/middleware/httpsredirect.py            |      3 [31m-[m
 .../fastapi/middleware/trustedhost.py              |      3 [31m-[m
 .../Lib/site-packages/fastapi/middleware/wsgi.py   |      1 [31m-[m
 .../Lib/site-packages/fastapi/openapi/__init__.py  |      0
 .../openapi/__pycache__/__init__.cpython-312.pyc   |    Bin [31m177[m -> [32m0[m bytes
 .../openapi/__pycache__/constants.cpython-312.pyc  |    Bin [31m347[m -> [32m0[m bytes
 .../openapi/__pycache__/docs.cpython-312.pyc       |    Bin [31m10781[m -> [32m0[m bytes
 .../openapi/__pycache__/models.cpython-312.pyc     |    Bin [31m22741[m -> [32m0[m bytes
 .../openapi/__pycache__/utils.cpython-312.pyc      |    Bin [31m21080[m -> [32m0[m bytes
 .../Lib/site-packages/fastapi/openapi/constants.py |      3 [31m-[m
 .../venv/Lib/site-packages/fastapi/openapi/docs.py |    344 [31m-[m
 .../Lib/site-packages/fastapi/openapi/models.py    |    438 [31m-[m
 .../Lib/site-packages/fastapi/openapi/utils.py     |    569 [31m-[m
 .../Lib/site-packages/fastapi/param_functions.py   |   2382 [31m-[m
 backend/venv/Lib/site-packages/fastapi/params.py   |    769 [31m-[m
 backend/venv/Lib/site-packages/fastapi/py.typed    |      0
 backend/venv/Lib/site-packages/fastapi/requests.py |      2 [31m-[m
 .../venv/Lib/site-packages/fastapi/responses.py    |     48 [31m-[m
 backend/venv/Lib/site-packages/fastapi/routing.py  |   4583 [31m-[m
 .../Lib/site-packages/fastapi/security/__init__.py |     15 [31m-[m
 .../security/__pycache__/__init__.cpython-312.pyc  |    Bin [31m834[m -> [32m0[m bytes
 .../security/__pycache__/api_key.cpython-312.pyc   |    Bin [31m10471[m -> [32m0[m bytes
 .../security/__pycache__/base.cpython-312.pyc      |    Bin [31m496[m -> [32m0[m bytes
 .../security/__pycache__/http.cpython-312.pyc      |    Bin [31m14524[m -> [32m0[m bytes
 .../security/__pycache__/oauth2.cpython-312.pyc    |    Bin [31m19237[m -> [32m0[m bytes
 .../open_id_connect_url.cpython-312.pyc            |    Bin [31m3750[m -> [32m0[m bytes
 .../security/__pycache__/utils.cpython-312.pyc     |    Bin [31m580[m -> [32m0[m bytes
 .../Lib/site-packages/fastapi/security/api_key.py  |    318 [31m-[m
 .../Lib/site-packages/fastapi/security/base.py     |      6 [31m-[m
 .../Lib/site-packages/fastapi/security/http.py     |    423 [31m-[m
 .../Lib/site-packages/fastapi/security/oauth2.py   |    663 [31m-[m
 .../fastapi/security/open_id_connect_url.py        |     94 [31m-[m
 .../Lib/site-packages/fastapi/security/utils.py    |     10 [31m-[m
 .../venv/Lib/site-packages/fastapi/staticfiles.py  |      1 [31m-[m
 .../fastapi/temp_pydantic_v1_params.py             |    717 [31m-[m
 .../venv/Lib/site-packages/fastapi/templating.py   |      1 [31m-[m
 .../venv/Lib/site-packages/fastapi/testclient.py   |      1 [31m-[m
 backend/venv/Lib/site-packages/fastapi/types.py    |     11 [31m-[m
 backend/venv/Lib/site-packages/fastapi/utils.py    |    250 [31m-[m
 .../venv/Lib/site-packages/fastapi/websockets.py   |      3 [31m-[m
 .../filelock-3.20.1.dist-info/INSTALLER            |      1 [31m-[m
 .../filelock-3.20.1.dist-info/METADATA             |     42 [31m-[m
 .../site-packages/filelock-3.20.1.dist-info/RECORD |     24 [31m-[m
 .../site-packages/filelock-3.20.1.dist-info/WHEEL  |      4 [31m-[m
 .../filelock-3.20.1.dist-info/licenses/LICENSE     |     24 [31m-[m
 .../venv/Lib/site-packages/filelock/__init__.py    |     70 [31m-[m
 .../filelock/__pycache__/__init__.cpython-312.pyc  |    Bin [31m1557[m -> [32m0[m bytes
 .../filelock/__pycache__/_api.cpython-312.pyc      |    Bin [31m16605[m -> [32m0[m bytes
 .../filelock/__pycache__/_error.cpython-312.pyc    |    Bin [31m1746[m -> [32m0[m bytes
 .../filelock/__pycache__/_soft.cpython-312.pyc     |    Bin [31m2439[m -> [32m0[m bytes
 .../filelock/__pycache__/_unix.cpython-312.pyc     |    Bin [31m3584[m -> [32m0[m bytes
 .../filelock/__pycache__/_util.cpython-312.pyc     |    Bin [31m1992[m -> [32m0[m bytes
 .../filelock/__pycache__/_windows.cpython-312.pyc  |    Bin [31m4638[m -> [32m0[m bytes
 .../filelock/__pycache__/asyncio.cpython-312.pyc   |    Bin [31m15580[m -> [32m0[m bytes
 .../filelock/__pycache__/version.cpython-312.pyc   |    Bin [31m778[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/filelock/_api.py    |    403 [31m-[m
 backend/venv/Lib/site-packages/filelock/_error.py  |     30 [31m-[m
 backend/venv/Lib/site-packages/filelock/_soft.py   |     47 [31m-[m
 backend/venv/Lib/site-packages/filelock/_unix.py   |     70 [31m-[m
 backend/venv/Lib/site-packages/filelock/_util.py   |     52 [31m-[m
 .../venv/Lib/site-packages/filelock/_windows.py    |    103 [31m-[m
 backend/venv/Lib/site-packages/filelock/asyncio.py |    344 [31m-[m
 backend/venv/Lib/site-packages/filelock/py.typed   |      0
 backend/venv/Lib/site-packages/filelock/version.py |     34 [31m-[m
 .../frozenlist-1.8.0.dist-info/INSTALLER           |      1 [31m-[m
 .../frozenlist-1.8.0.dist-info/METADATA            |    672 [31m-[m
 .../frozenlist-1.8.0.dist-info/RECORD              |     12 [31m-[m
 .../site-packages/frozenlist-1.8.0.dist-info/WHEEL |      5 [31m-[m
 .../frozenlist-1.8.0.dist-info/licenses/LICENSE    |    201 [31m-[m
 .../frozenlist-1.8.0.dist-info/top_level.txt       |      1 [31m-[m
 .../venv/Lib/site-packages/frozenlist/__init__.py  |     86 [31m-[m
 .../venv/Lib/site-packages/frozenlist/__init__.pyi |     47 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m4049[m -> [32m0[m bytes
 .../frozenlist/_frozenlist.cp312-win_amd64.pyd     |    Bin [31m69632[m -> [32m0[m bytes
 .../Lib/site-packages/frozenlist/_frozenlist.pyx   |    148 [31m-[m
 backend/venv/Lib/site-packages/frozenlist/py.typed |      1 [31m-[m
 .../fsspec-2025.12.0.dist-info/INSTALLER           |      1 [31m-[m
 .../fsspec-2025.12.0.dist-info/METADATA            |    256 [31m-[m
 .../fsspec-2025.12.0.dist-info/RECORD              |    119 [31m-[m
 .../site-packages/fsspec-2025.12.0.dist-info/WHEEL |      4 [31m-[m
 .../fsspec-2025.12.0.dist-info/licenses/LICENSE    |     29 [31m-[m
 backend/venv/Lib/site-packages/fsspec/__init__.py  |     71 [31m-[m
 .../fsspec/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1891[m -> [32m0[m bytes
 .../fsspec/__pycache__/_version.cpython-312.pyc    |    Bin [31m780[m -> [32m0[m bytes
 .../fsspec/__pycache__/archive.cpython-312.pyc     |    Bin [31m4097[m -> [32m0[m bytes
 .../fsspec/__pycache__/asyn.cpython-312.pyc        |    Bin [31m45716[m -> [32m0[m bytes
 .../fsspec/__pycache__/caching.cpython-312.pyc     |    Bin [31m41403[m -> [32m0[m bytes
 .../fsspec/__pycache__/callbacks.cpython-312.pyc   |    Bin [31m12908[m -> [32m0[m bytes
 .../fsspec/__pycache__/compression.cpython-312.pyc |    Bin [31m7387[m -> [32m0[m bytes
 .../fsspec/__pycache__/config.cpython-312.pyc      |    Bin [31m5973[m -> [32m0[m bytes
 .../fsspec/__pycache__/conftest.cpython-312.pyc    |    Bin [31m6190[m -> [32m0[m bytes
 .../fsspec/__pycache__/core.cpython-312.pyc        |    Bin [31m28486[m -> [32m0[m bytes
 .../fsspec/__pycache__/dircache.cpython-312.pyc    |    Bin [31m4512[m -> [32m0[m bytes
 .../fsspec/__pycache__/exceptions.cpython-312.pyc  |    Bin [31m824[m -> [32m0[m bytes
 .../fsspec/__pycache__/fuse.cpython-312.pyc        |    Bin [31m15653[m -> [32m0[m bytes
 .../fsspec/__pycache__/generic.cpython-312.pyc     |    Bin [31m18257[m -> [32m0[m bytes
 .../fsspec/__pycache__/gui.cpython-312.pyc         |    Bin [31m21623[m -> [32m0[m bytes
 .../fsspec/__pycache__/json.cpython-312.pyc        |    Bin [31m6123[m -> [32m0[m bytes
 .../fsspec/__pycache__/mapping.cpython-312.pyc     |    Bin [31m12234[m -> [32m0[m bytes
 .../fsspec/__pycache__/parquet.cpython-312.pyc     |    Bin [31m17955[m -> [32m0[m bytes
 .../fsspec/__pycache__/registry.cpython-312.pyc    |    Bin [31m11530[m -> [32m0[m bytes
 .../fsspec/__pycache__/spec.cpython-312.pyc        |    Bin [31m91138[m -> [32m0[m bytes
 .../fsspec/__pycache__/transaction.cpython-312.pyc |    Bin [31m4576[m -> [32m0[m bytes
 .../fsspec/__pycache__/utils.cpython-312.pyc       |    Bin [31m28551[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/fsspec/_version.py  |     34 [31m-[m
 backend/venv/Lib/site-packages/fsspec/archive.py   |     75 [31m-[m
 backend/venv/Lib/site-packages/fsspec/asyn.py      |   1103 [31m-[m
 backend/venv/Lib/site-packages/fsspec/caching.py   |   1011 [31m-[m
 backend/venv/Lib/site-packages/fsspec/callbacks.py |    324 [31m-[m
 .../venv/Lib/site-packages/fsspec/compression.py   |    182 [31m-[m
 backend/venv/Lib/site-packages/fsspec/config.py    |    131 [31m-[m
 backend/venv/Lib/site-packages/fsspec/conftest.py  |    125 [31m-[m
 backend/venv/Lib/site-packages/fsspec/core.py      |    760 [31m-[m
 backend/venv/Lib/site-packages/fsspec/dircache.py  |     98 [31m-[m
 .../venv/Lib/site-packages/fsspec/exceptions.py    |     18 [31m-[m
 backend/venv/Lib/site-packages/fsspec/fuse.py      |    324 [31m-[m
 backend/venv/Lib/site-packages/fsspec/generic.py   |    396 [31m-[m
 backend/venv/Lib/site-packages/fsspec/gui.py       |    417 [31m-[m
 .../fsspec/implementations/__init__.py             |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m184[m -> [32m0[m bytes
 .../__pycache__/arrow.cpython-312.pyc              |    Bin [31m14006[m -> [32m0[m bytes
 .../__pycache__/asyn_wrapper.cpython-312.pyc       |    Bin [31m5577[m -> [32m0[m bytes
 .../__pycache__/cache_mapper.cpython-312.pyc       |    Bin [31m3989[m -> [32m0[m bytes
 .../__pycache__/cache_metadata.cpython-312.pyc     |    Bin [31m11118[m -> [32m0[m bytes
 .../__pycache__/cached.cpython-312.pyc             |    Bin [31m46857[m -> [32m0[m bytes
 .../__pycache__/chained.cpython-312.pyc            |    Bin [31m1076[m -> [32m0[m bytes
 .../__pycache__/dask.cpython-312.pyc               |    Bin [31m7090[m -> [32m0[m bytes
 .../__pycache__/data.cpython-312.pyc               |    Bin [31m2991[m -> [32m0[m bytes
 .../__pycache__/dbfs.cpython-312.pyc               |    Bin [31m19437[m -> [32m0[m bytes
 .../__pycache__/dirfs.cpython-312.pyc              |    Bin [31m24907[m -> [32m0[m bytes
 .../__pycache__/ftp.cpython-312.pyc                |    Bin [31m17265[m -> [32m0[m bytes
 .../__pycache__/gist.cpython-312.pyc               |    Bin [31m9865[m -> [32m0[m bytes
 .../__pycache__/git.cpython-312.pyc                |    Bin [31m5906[m -> [32m0[m bytes
 .../__pycache__/github.cpython-312.pyc             |    Bin [31m14493[m -> [32m0[m bytes
 .../__pycache__/http.cpython-312.pyc               |    Bin [31m42269[m -> [32m0[m bytes
 .../__pycache__/http_sync.cpython-312.pyc          |    Bin [31m40140[m -> [32m0[m bytes
 .../__pycache__/jupyter.cpython-312.pyc            |    Bin [31m6807[m -> [32m0[m bytes
 .../__pycache__/libarchive.cpython-312.pyc         |    Bin [31m8637[m -> [32m0[m bytes
 .../__pycache__/local.cpython-312.pyc              |    Bin [31m25533[m -> [32m0[m bytes
 .../__pycache__/memory.cpython-312.pyc             |    Bin [31m14255[m -> [32m0[m bytes
 .../__pycache__/reference.cpython-312.pyc          |    Bin [31m64630[m -> [32m0[m bytes
 .../__pycache__/sftp.cpython-312.pyc               |    Bin [31m10125[m -> [32m0[m bytes
 .../__pycache__/smb.cpython-312.pyc                |    Bin [31m19210[m -> [32m0[m bytes
 .../__pycache__/tar.cpython-312.pyc                |    Bin [31m4665[m -> [32m0[m bytes
 .../__pycache__/webhdfs.cpython-312.pyc            |    Bin [31m22866[m -> [32m0[m bytes
 .../__pycache__/zip.cpython-312.pyc                |    Bin [31m8285[m -> [32m0[m bytes
 .../site-packages/fsspec/implementations/arrow.py  |    310 [31m-[m
 .../fsspec/implementations/asyn_wrapper.py         |    124 [31m-[m
 .../fsspec/implementations/cache_mapper.py         |     75 [31m-[m
 .../fsspec/implementations/cache_metadata.py       |    231 [31m-[m
 .../site-packages/fsspec/implementations/cached.py |   1003 [31m-[m
 .../fsspec/implementations/chained.py              |     23 [31m-[m
 .../site-packages/fsspec/implementations/dask.py   |    152 [31m-[m
 .../site-packages/fsspec/implementations/data.py   |     57 [31m-[m
 .../site-packages/fsspec/implementations/dbfs.py   |    496 [31m-[m
 .../site-packages/fsspec/implementations/dirfs.py  |    389 [31m-[m
 .../site-packages/fsspec/implementations/ftp.py    |    387 [31m-[m
 .../site-packages/fsspec/implementations/gist.py   |    241 [31m-[m
 .../site-packages/fsspec/implementations/git.py    |    114 [31m-[m
 .../site-packages/fsspec/implementations/github.py |    333 [31m-[m
 .../site-packages/fsspec/implementations/http.py   |    897 [31m-[m
 .../fsspec/implementations/http_sync.py            |    937 [31m-[m
 .../fsspec/implementations/jupyter.py              |    129 [31m-[m
 .../fsspec/implementations/libarchive.py           |    213 [31m-[m
 .../site-packages/fsspec/implementations/local.py  |    514 [31m-[m
 .../site-packages/fsspec/implementations/memory.py |    311 [31m-[m
 .../fsspec/implementations/reference.py            |   1311 [31m-[m
 .../site-packages/fsspec/implementations/sftp.py   |    187 [31m-[m
 .../site-packages/fsspec/implementations/smb.py    |    416 [31m-[m
 .../site-packages/fsspec/implementations/tar.py    |    124 [31m-[m
 .../fsspec/implementations/webhdfs.py              |    485 [31m-[m
 .../site-packages/fsspec/implementations/zip.py    |    177 [31m-[m
 backend/venv/Lib/site-packages/fsspec/json.py      |    112 [31m-[m
 backend/venv/Lib/site-packages/fsspec/mapping.py   |    251 [31m-[m
 backend/venv/Lib/site-packages/fsspec/parquet.py   |    580 [31m-[m
 backend/venv/Lib/site-packages/fsspec/registry.py  |    333 [31m-[m
 backend/venv/Lib/site-packages/fsspec/spec.py      |   2281 [31m-[m
 .../fsspec/tests/abstract/__init__.py              |    289 [31m-[m
 .../abstract/__pycache__/__init__.cpython-312.pyc  |    Bin [31m13911[m -> [32m0[m bytes
 .../abstract/__pycache__/common.cpython-312.pyc    |    Bin [31m2131[m -> [32m0[m bytes
 .../abstract/__pycache__/copy.cpython-312.pyc      |    Bin [31m20970[m -> [32m0[m bytes
 .../tests/abstract/__pycache__/get.cpython-312.pyc |    Bin [31m20806[m -> [32m0[m bytes
 .../tests/abstract/__pycache__/mv.cpython-312.pyc  |    Bin [31m2514[m -> [32m0[m bytes
 .../abstract/__pycache__/open.cpython-312.pyc      |    Bin [31m1143[m -> [32m0[m bytes
 .../abstract/__pycache__/pipe.cpython-312.pyc      |    Bin [31m1072[m -> [32m0[m bytes
 .../tests/abstract/__pycache__/put.cpython-312.pyc |    Bin [31m21963[m -> [32m0[m bytes
 .../site-packages/fsspec/tests/abstract/common.py  |    175 [31m-[m
 .../site-packages/fsspec/tests/abstract/copy.py    |    557 [31m-[m
 .../Lib/site-packages/fsspec/tests/abstract/get.py |    587 [31m-[m
 .../Lib/site-packages/fsspec/tests/abstract/mv.py  |     57 [31m-[m
 .../site-packages/fsspec/tests/abstract/open.py    |     11 [31m-[m
 .../site-packages/fsspec/tests/abstract/pipe.py    |     11 [31m-[m
 .../Lib/site-packages/fsspec/tests/abstract/put.py |    591 [31m-[m
 .../venv/Lib/site-packages/fsspec/transaction.py   |     90 [31m-[m
 backend/venv/Lib/site-packages/fsspec/utils.py     |    738 [31m-[m
 .../Lib/site-packages/google/_upb/_message.pyd     |    Bin [31m713235[m -> [32m0[m bytes
 .../google/ai/generativelanguage/__init__.py       |    426 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m9051[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m224[m -> [32m0[m bytes
 .../google/ai/generativelanguage/gapic_version.py  |     16 [31m-[m
 .../google/ai/generativelanguage/py.typed          |      2 [31m-[m
 .../google/ai/generativelanguage_v1/__init__.py    |     89 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1776[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m227[m -> [32m0[m bytes
 .../ai/generativelanguage_v1/gapic_metadata.json   |    152 [31m-[m
 .../ai/generativelanguage_v1/gapic_version.py      |     16 [31m-[m
 .../google/ai/generativelanguage_v1/py.typed       |      2 [31m-[m
 .../ai/generativelanguage_v1/services/__init__.py  |     15 [31m-[m
 .../services/__pycache__/__init__.cpython-312.pyc  |    Bin [31m202[m -> [32m0[m bytes
 .../services/generative_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m378[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m46850[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m61339[m -> [32m0[m bytes
 .../services/generative_service/async_client.py    |   1150 [31m-[m
 .../services/generative_service/client.py          |   1529 [31m-[m
 .../generative_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m804[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m11300[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m23484[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m27293[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m60160[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m19843[m -> [32m0[m bytes
 .../services/generative_service/transports/base.py |    320 [31m-[m
 .../services/generative_service/transports/grpc.py |    547 [31m-[m
 .../generative_service/transports/grpc_asyncio.py  |    650 [31m-[m
 .../services/generative_service/transports/rest.py |   1643 [31m-[m
 .../generative_service/transports/rest_base.py     |    484 [31m-[m
 .../services/model_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m363[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m29781[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m44975[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m9949[m -> [32m0[m bytes
 .../services/model_service/async_client.py         |    720 [31m-[m
 .../services/model_service/client.py               |   1107 [31m-[m
 .../services/model_service/pagers.py               |    197 [31m-[m
 .../services/model_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m774[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m8520[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m19275[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m21552[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m38177[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m11692[m -> [32m0[m bytes
 .../services/model_service/transports/base.py      |    220 [31m-[m
 .../services/model_service/transports/grpc.py      |    443 [31m-[m
 .../model_service/transports/grpc_asyncio.py       |    489 [31m-[m
 .../services/model_service/transports/rest.py      |   1018 [31m-[m
 .../services/model_service/transports/rest_base.py |    268 [31m-[m
 .../ai/generativelanguage_v1/types/__init__.py     |     75 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1365[m -> [32m0[m bytes
 .../types/__pycache__/citation.cpython-312.pyc     |    Bin [31m3163[m -> [32m0[m bytes
 .../types/__pycache__/content.cpython-312.pyc      |    Bin [31m4516[m -> [32m0[m bytes
 .../__pycache__/generative_service.cpython-312.pyc |    Bin [31m45855[m -> [32m0[m bytes
 .../types/__pycache__/model.cpython-312.pyc        |    Bin [31m5857[m -> [32m0[m bytes
 .../__pycache__/model_service.cpython-312.pyc      |    Bin [31m3760[m -> [32m0[m bytes
 .../types/__pycache__/safety.cpython-312.pyc       |    Bin [31m7378[m -> [32m0[m bytes
 .../ai/generativelanguage_v1/types/citation.py     |    101 [31m-[m
 .../ai/generativelanguage_v1/types/content.py      |    133 [31m-[m
 .../types/generative_service.py                    |   1129 [31m-[m
 .../google/ai/generativelanguage_v1/types/model.py |    171 [31m-[m
 .../generativelanguage_v1/types/model_service.py   |    112 [31m-[m
 .../ai/generativelanguage_v1/types/safety.py       |    197 [31m-[m
 .../ai/generativelanguage_v1alpha/__init__.py      |    413 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m7802[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m232[m -> [32m0[m bytes
 .../generativelanguage_v1alpha/gapic_metadata.json |   1020 [31m-[m
 .../ai/generativelanguage_v1alpha/gapic_version.py |     16 [31m-[m
 .../google/ai/generativelanguage_v1alpha/py.typed  |      2 [31m-[m
 .../services/__init__.py                           |     15 [31m-[m
 .../services/__pycache__/__init__.cpython-312.pyc  |    Bin [31m207[m -> [32m0[m bytes
 .../services/cache_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m368[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m38601[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m53969[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m10287[m -> [32m0[m bytes
 .../services/cache_service/async_client.py         |    950 [31m-[m
 .../services/cache_service/client.py               |   1340 [31m-[m
 .../services/cache_service/pagers.py               |    197 [31m-[m
 .../services/cache_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m779[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9918[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m22011[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m24636[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m51665[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m16660[m -> [32m0[m bytes
 .../services/cache_service/transports/base.py      |    263 [31m-[m
 .../services/cache_service/transports/grpc.py      |    517 [31m-[m
 .../cache_service/transports/grpc_asyncio.py       |    573 [31m-[m
 .../services/cache_service/transports/rest.py      |   1428 [31m-[m
 .../services/cache_service/transports/rest_base.py |    399 [31m-[m
 .../services/discuss_service/__init__.py           |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m374[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m30751[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m46086[m -> [32m0[m bytes
 .../services/discuss_service/async_client.py       |    740 [31m-[m
 .../services/discuss_service/client.py             |   1128 [31m-[m
 .../discuss_service/transports/__init__.py         |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m791[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m8170[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m18556[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m20703[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m34401[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m11524[m -> [32m0[m bytes
 .../services/discuss_service/transports/base.py    |    213 [31m-[m
 .../services/discuss_service/transports/grpc.py    |    431 [31m-[m
 .../discuss_service/transports/grpc_asyncio.py     |    468 [31m-[m
 .../services/discuss_service/transports/rest.py    |    909 [31m-[m
 .../discuss_service/transports/rest_base.py        |    268 [31m-[m
 .../services/file_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m365[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m32060[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m46998[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m9963[m -> [32m0[m bytes
 .../services/file_service/async_client.py          |    780 [31m-[m
 .../services/file_service/client.py                |   1165 [31m-[m
 .../services/file_service/pagers.py                |    197 [31m-[m
 .../services/file_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m773[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9171[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m20287[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m22740[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m43972[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m13596[m -> [32m0[m bytes
 .../services/file_service/transports/base.py       |    239 [31m-[m
 .../services/file_service/transports/grpc.py       |    472 [31m-[m
 .../file_service/transports/grpc_asyncio.py        |    523 [31m-[m
 .../services/file_service/transports/rest.py       |   1191 [31m-[m
 .../services/file_service/transports/rest_base.py  |    323 [31m-[m
 .../services/generative_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m383[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m56373[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m71142[m -> [32m0[m bytes
 .../services/generative_service/async_client.py    |   1366 [31m-[m
 .../services/generative_service/client.py          |   1751 [31m-[m
 .../generative_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m809[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m10996[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m25316[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m28275[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m63421[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m20972[m -> [32m0[m bytes
 .../services/generative_service/transports/base.py |    298 [31m-[m
 .../services/generative_service/transports/grpc.py |    591 [31m-[m
 .../generative_service/transports/grpc_asyncio.py  |    654 [31m-[m
 .../services/generative_service/transports/rest.py |   1726 [31m-[m
 .../generative_service/transports/rest_base.py     |    510 [31m-[m
 .../services/model_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m368[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m49866[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m64770[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m18308[m -> [32m0[m bytes
 .../services/model_service/async_client.py         |   1261 [31m-[m
 .../services/model_service/client.py               |   1646 [31m-[m
 .../services/model_service/pagers.py               |    353 [31m-[m
 .../services/model_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m779[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m11202[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m25053[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m28010[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m65471[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m19557[m -> [32m0[m bytes
 .../services/model_service/transports/base.py      |    290 [31m-[m
 .../services/model_service/transports/grpc.py      |    582 [31m-[m
 .../model_service/transports/grpc_asyncio.py       |    655 [31m-[m
 .../services/model_service/transports/rest.py      |   1819 [31m-[m
 .../services/model_service/transports/rest_base.py |    476 [31m-[m
 .../services/permission_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m383[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m46041[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m60819[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m10191[m -> [32m0[m bytes
 .../services/permission_service/async_client.py    |   1150 [31m-[m
 .../services/permission_service/client.py          |   1532 [31m-[m
 .../services/permission_service/pagers.py          |    197 [31m-[m
 .../permission_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m809[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m10485[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m22923[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m25726[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m60671[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m20034[m -> [32m0[m bytes
 .../services/permission_service/transports/base.py |    272 [31m-[m
 .../services/permission_service/transports/grpc.py |    541 [31m-[m
 .../permission_service/transports/grpc_asyncio.py  |    604 [31m-[m
 .../services/permission_service/transports/rest.py |   1671 [31m-[m
 .../permission_service/transports/rest_base.py     |    493 [31m-[m
 .../services/prediction_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m383[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m23116[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m38750[m -> [32m0[m bytes
 .../services/prediction_service/async_client.py    |    535 [31m-[m
 .../services/prediction_service/client.py          |    929 [31m-[m
 .../prediction_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m809[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7593[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m17155[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m19152[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m27213[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m9296[m -> [32m0[m bytes
 .../services/prediction_service/transports/base.py |    196 [31m-[m
 .../services/prediction_service/transports/grpc.py |    396 [31m-[m
 .../prediction_service/transports/grpc_asyncio.py  |    429 [31m-[m
 .../services/prediction_service/transports/rest.py |    700 [31m-[m
 .../prediction_service/transports/rest_base.py     |    211 [31m-[m
 .../services/retriever_service/__init__.py         |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m380[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m96543[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m109934[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m26371[m -> [32m0[m bytes
 .../services/retriever_service/async_client.py     |   2499 [31m-[m
 .../services/retriever_service/client.py           |   2875 [31m-[m
 .../services/retriever_service/pagers.py           |    509 [31m-[m
 .../retriever_service/transports/__init__.py       |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m803[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m17973[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m37041[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m42224[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m140826[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m46134[m -> [32m0[m bytes
 .../services/retriever_service/transports/base.py  |    481 [31m-[m
 .../services/retriever_service/transports/grpc.py  |    908 [31m-[m
 .../retriever_service/transports/grpc_asyncio.py   |   1048 [31m-[m
 .../services/retriever_service/transports/rest.py  |   4067 [31m-[m
 .../retriever_service/transports/rest_base.py      |   1196 [31m-[m
 .../services/text_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m365[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m40742[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m55551[m -> [32m0[m bytes
 .../services/text_service/async_client.py          |   1005 [31m-[m
 .../services/text_service/client.py                |   1386 [31m-[m
 .../services/text_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m773[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9198[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m20679[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m23139[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m46784[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m15799[m -> [32m0[m bytes
 .../services/text_service/transports/base.py       |    246 [31m-[m
 .../services/text_service/transports/grpc.py       |    485 [31m-[m
 .../text_service/transports/grpc_asyncio.py        |    536 [31m-[m
 .../services/text_service/transports/rest.py       |   1293 [31m-[m
 .../services/text_service/transports/rest_base.py  |    387 [31m-[m
 .../generativelanguage_v1alpha/types/__init__.py   |    369 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m6488[m -> [32m0[m bytes
 .../__pycache__/cache_service.cpython-312.pyc      |    Bin [31m5902[m -> [32m0[m bytes
 .../__pycache__/cached_content.cpython-312.pyc     |    Bin [31m6812[m -> [32m0[m bytes
 .../types/__pycache__/citation.cpython-312.pyc     |    Bin [31m3178[m -> [32m0[m bytes
 .../types/__pycache__/content.cpython-312.pyc      |    Bin [31m31525[m -> [32m0[m bytes
 .../__pycache__/discuss_service.cpython-312.pyc    |    Bin [31m13274[m -> [32m0[m bytes
 .../types/__pycache__/file.cpython-312.pyc         |    Bin [31m6302[m -> [32m0[m bytes
 .../types/__pycache__/file_service.cpython-312.pyc |    Bin [31m4651[m -> [32m0[m bytes
 .../__pycache__/generative_service.cpython-312.pyc |    Bin [31m89294[m -> [32m0[m bytes
 .../types/__pycache__/model.cpython-312.pyc        |    Bin [31m5867[m -> [32m0[m bytes
 .../__pycache__/model_service.cpython-312.pyc      |    Bin [31m12102[m -> [32m0[m bytes
 .../types/__pycache__/permission.cpython-312.pyc   |    Bin [31m4971[m -> [32m0[m bytes
 .../__pycache__/permission_service.cpython-312.pyc |    Bin [31m8057[m -> [32m0[m bytes
 .../__pycache__/prediction_service.cpython-312.pyc |    Bin [31m2659[m -> [32m0[m bytes
 .../types/__pycache__/retriever.cpython-312.pyc    |    Bin [31m16109[m -> [32m0[m bytes
 .../__pycache__/retriever_service.cpython-312.pyc  |    Bin [31m30483[m -> [32m0[m bytes
 .../types/__pycache__/safety.cpython-312.pyc       |    Bin [31m10466[m -> [32m0[m bytes
 .../types/__pycache__/text_service.cpython-312.pyc |    Bin [31m17084[m -> [32m0[m bytes
 .../types/__pycache__/tuned_model.cpython-312.pyc  |    Bin [31m20463[m -> [32m0[m bytes
 .../types/cache_service.py                         |    167 [31m-[m
 .../types/cached_content.py                        |    182 [31m-[m
 .../generativelanguage_v1alpha/types/citation.py   |    101 [31m-[m
 .../ai/generativelanguage_v1alpha/types/content.py |    819 [31m-[m
 .../types/discuss_service.py                       |    356 [31m-[m
 .../ai/generativelanguage_v1alpha/types/file.py    |    174 [31m-[m
 .../types/file_service.py                          |    145 [31m-[m
 .../types/generative_service.py                    |   2139 [31m-[m
 .../ai/generativelanguage_v1alpha/types/model.py   |    171 [31m-[m
 .../types/model_service.py                         |    332 [31m-[m
 .../generativelanguage_v1alpha/types/permission.py |    141 [31m-[m
 .../types/permission_service.py                    |    220 [31m-[m
 .../types/prediction_service.py                    |     79 [31m-[m
 .../generativelanguage_v1alpha/types/retriever.py  |    411 [31m-[m
 .../types/retriever_service.py                     |    793 [31m-[m
 .../ai/generativelanguage_v1alpha/types/safety.py  |    276 [31m-[m
 .../types/text_service.py                          |    441 [31m-[m
 .../types/tuned_model.py                           |    542 [31m-[m
 .../ai/generativelanguage_v1beta/__init__.py       |    387 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m7218[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m231[m -> [32m0[m bytes
 .../generativelanguage_v1beta/gapic_metadata.json  |   1005 [31m-[m
 .../ai/generativelanguage_v1beta/gapic_version.py  |     16 [31m-[m
 .../google/ai/generativelanguage_v1beta/py.typed   |      2 [31m-[m
 .../generativelanguage_v1beta/services/__init__.py |     15 [31m-[m
 .../services/__pycache__/__init__.cpython-312.pyc  |    Bin [31m206[m -> [32m0[m bytes
 .../services/cache_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m367[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m38569[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m53937[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m10277[m -> [32m0[m bytes
 .../services/cache_service/async_client.py         |    950 [31m-[m
 .../services/cache_service/client.py               |   1340 [31m-[m
 .../services/cache_service/pagers.py               |    197 [31m-[m
 .../services/cache_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m778[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9915[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m22003[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m24628[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m51649[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m16650[m -> [32m0[m bytes
 .../services/cache_service/transports/base.py      |    263 [31m-[m
 .../services/cache_service/transports/grpc.py      |    517 [31m-[m
 .../cache_service/transports/grpc_asyncio.py       |    573 [31m-[m
 .../services/cache_service/transports/rest.py      |   1428 [31m-[m
 .../services/cache_service/transports/rest_base.py |    399 [31m-[m
 .../services/discuss_service/__init__.py           |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m373[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m30732[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m46067[m -> [32m0[m bytes
 .../services/discuss_service/async_client.py       |    740 [31m-[m
 .../services/discuss_service/client.py             |   1128 [31m-[m
 .../discuss_service/transports/__init__.py         |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m790[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m8675[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m18551[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m21215[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m34390[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m11515[m -> [32m0[m bytes
 .../services/discuss_service/transports/base.py    |    231 [31m-[m
 .../services/discuss_service/transports/grpc.py    |    431 [31m-[m
 .../discuss_service/transports/grpc_asyncio.py     |    486 [31m-[m
 .../services/discuss_service/transports/rest.py    |    909 [31m-[m
 .../discuss_service/transports/rest_base.py        |    268 [31m-[m
 .../services/file_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m364[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m32035[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m46973[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m9953[m -> [32m0[m bytes
 .../services/file_service/async_client.py          |    780 [31m-[m
 .../services/file_service/client.py                |   1165 [31m-[m
 .../services/file_service/pagers.py                |    197 [31m-[m
 .../services/file_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m772[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9168[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m20280[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m22733[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m43958[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m13587[m -> [32m0[m bytes
 .../services/file_service/transports/base.py       |    239 [31m-[m
 .../services/file_service/transports/grpc.py       |    472 [31m-[m
 .../file_service/transports/grpc_asyncio.py        |    523 [31m-[m
 .../services/file_service/transports/rest.py       |   1191 [31m-[m
 .../services/file_service/transports/rest_base.py  |    323 [31m-[m
 .../services/generative_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m382[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m52428[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m67353[m -> [32m0[m bytes
 .../services/generative_service/async_client.py    |   1272 [31m-[m
 .../services/generative_service/client.py          |   1659 [31m-[m
 .../generative_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m808[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m11584[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m23993[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m27994[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m61723[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m20550[m -> [32m0[m bytes
 .../services/generative_service/transports/base.py |    335 [31m-[m
 .../services/generative_service/transports/grpc.py |    560 [31m-[m
 .../generative_service/transports/grpc_asyncio.py  |    672 [31m-[m
 .../services/generative_service/transports/rest.py |   1696 [31m-[m
 .../generative_service/transports/rest_base.py     |    506 [31m-[m
 .../services/model_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m367[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m49824[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m64728[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m18290[m -> [32m0[m bytes
 .../services/model_service/async_client.py         |   1261 [31m-[m
 .../services/model_service/client.py               |   1646 [31m-[m
 .../services/model_service/pagers.py               |    353 [31m-[m
 .../services/model_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m778[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m12542[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m25043[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m29362[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m65445[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m19545[m -> [32m0[m bytes
 .../services/model_service/transports/base.py      |    353 [31m-[m
 .../services/model_service/transports/grpc.py      |    582 [31m-[m
 .../model_service/transports/grpc_asyncio.py       |    718 [31m-[m
 .../services/model_service/transports/rest.py      |   1819 [31m-[m
 .../services/model_service/transports/rest_base.py |    476 [31m-[m
 .../services/permission_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m382[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m46004[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m60782[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m10181[m -> [32m0[m bytes
 .../services/permission_service/async_client.py    |   1150 [31m-[m
 .../services/permission_service/client.py          |   1532 [31m-[m
 .../services/permission_service/pagers.py          |    197 [31m-[m
 .../permission_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m808[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m11491[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m22914[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m26741[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m60653[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m20020[m -> [32m0[m bytes
 .../services/permission_service/transports/base.py |    317 [31m-[m
 .../services/permission_service/transports/grpc.py |    541 [31m-[m
 .../permission_service/transports/grpc_asyncio.py  |    649 [31m-[m
 .../services/permission_service/transports/rest.py |   1671 [31m-[m
 .../permission_service/transports/rest_base.py     |    493 [31m-[m
 .../services/prediction_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m382[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m23104[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m38738[m -> [32m0[m bytes
 .../services/prediction_service/async_client.py    |    535 [31m-[m
 .../services/prediction_service/client.py          |    929 [31m-[m
 .../prediction_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m808[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7590[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m17151[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m19148[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m27203[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m9288[m -> [32m0[m bytes
 .../services/prediction_service/transports/base.py |    196 [31m-[m
 .../services/prediction_service/transports/grpc.py |    396 [31m-[m
 .../prediction_service/transports/grpc_asyncio.py  |    429 [31m-[m
 .../services/prediction_service/transports/rest.py |    700 [31m-[m
 .../prediction_service/transports/rest_base.py     |    211 [31m-[m
 .../services/retriever_service/__init__.py         |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m379[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m96430[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m109821[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m26345[m -> [32m0[m bytes
 .../services/retriever_service/async_client.py     |   2499 [31m-[m
 .../services/retriever_service/client.py           |   2875 [31m-[m
 .../services/retriever_service/pagers.py           |    509 [31m-[m
 .../retriever_service/transports/__init__.py       |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m802[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m20822[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m37018[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m45090[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m140783[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m46113[m -> [32m0[m bytes
 .../services/retriever_service/transports/base.py  |    625 [31m-[m
 .../services/retriever_service/transports/grpc.py  |    908 [31m-[m
 .../retriever_service/transports/grpc_asyncio.py   |   1192 [31m-[m
 .../services/retriever_service/transports/rest.py  |   4067 [31m-[m
 .../retriever_service/transports/rest_base.py      |   1196 [31m-[m
 .../services/text_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m364[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m40713[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m55522[m -> [32m0[m bytes
 .../services/text_service/async_client.py          |   1005 [31m-[m
 .../services/text_service/client.py                |   1386 [31m-[m
 .../services/text_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m772[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m10038[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m20672[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m23988[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m46769[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m15787[m -> [32m0[m bytes
 .../services/text_service/transports/base.py       |    282 [31m-[m
 .../services/text_service/transports/grpc.py       |    485 [31m-[m
 .../text_service/transports/grpc_asyncio.py        |    572 [31m-[m
 .../services/text_service/transports/rest.py       |   1293 [31m-[m
 .../services/text_service/transports/rest_base.py  |    387 [31m-[m
 .../ai/generativelanguage_v1beta/types/__init__.py |    343 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m5905[m -> [32m0[m bytes
 .../__pycache__/cache_service.cpython-312.pyc      |    Bin [31m5896[m -> [32m0[m bytes
 .../__pycache__/cached_content.cpython-312.pyc     |    Bin [31m6804[m -> [32m0[m bytes
 .../types/__pycache__/citation.cpython-312.pyc     |    Bin [31m3175[m -> [32m0[m bytes
 .../types/__pycache__/content.cpython-312.pyc      |    Bin [31m31495[m -> [32m0[m bytes
 .../__pycache__/discuss_service.cpython-312.pyc    |    Bin [31m13261[m -> [32m0[m bytes
 .../types/__pycache__/file.cpython-312.pyc         |    Bin [31m6298[m -> [32m0[m bytes
 .../types/__pycache__/file_service.cpython-312.pyc |    Bin [31m4645[m -> [32m0[m bytes
 .../__pycache__/generative_service.cpython-312.pyc |    Bin [31m72855[m -> [32m0[m bytes
 .../types/__pycache__/model.cpython-312.pyc        |    Bin [31m5865[m -> [32m0[m bytes
 .../__pycache__/model_service.cpython-312.pyc      |    Bin [31m12094[m -> [32m0[m bytes
 .../types/__pycache__/permission.cpython-312.pyc   |    Bin [31m4967[m -> [32m0[m bytes
 .../__pycache__/permission_service.cpython-312.pyc |    Bin [31m8051[m -> [32m0[m bytes
 .../__pycache__/prediction_service.cpython-312.pyc |    Bin [31m2656[m -> [32m0[m bytes
 .../types/__pycache__/retriever.cpython-312.pyc    |    Bin [31m16100[m -> [32m0[m bytes
 .../__pycache__/retriever_service.cpython-312.pyc  |    Bin [31m30461[m -> [32m0[m bytes
 .../types/__pycache__/safety.cpython-312.pyc       |    Bin [31m10457[m -> [32m0[m bytes
 .../types/__pycache__/text_service.cpython-312.pyc |    Bin [31m17070[m -> [32m0[m bytes
 .../types/__pycache__/tuned_model.cpython-312.pyc  |    Bin [31m16590[m -> [32m0[m bytes
 .../types/cache_service.py                         |    167 [31m-[m
 .../types/cached_content.py                        |    182 [31m-[m
 .../ai/generativelanguage_v1beta/types/citation.py |    101 [31m-[m
 .../ai/generativelanguage_v1beta/types/content.py  |    819 [31m-[m
 .../types/discuss_service.py                       |    356 [31m-[m
 .../ai/generativelanguage_v1beta/types/file.py     |    174 [31m-[m
 .../types/file_service.py                          |    145 [31m-[m
 .../types/generative_service.py                    |   1751 [31m-[m
 .../ai/generativelanguage_v1beta/types/model.py    |    171 [31m-[m
 .../types/model_service.py                         |    332 [31m-[m
 .../generativelanguage_v1beta/types/permission.py  |    141 [31m-[m
 .../types/permission_service.py                    |    220 [31m-[m
 .../types/prediction_service.py                    |     79 [31m-[m
 .../generativelanguage_v1beta/types/retriever.py   |    411 [31m-[m
 .../types/retriever_service.py                     |    793 [31m-[m
 .../ai/generativelanguage_v1beta/types/safety.py   |    276 [31m-[m
 .../types/text_service.py                          |    441 [31m-[m
 .../generativelanguage_v1beta/types/tuned_model.py |    442 [31m-[m
 .../ai/generativelanguage_v1beta2/__init__.py      |     85 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1704[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m232[m -> [32m0[m bytes
 .../generativelanguage_v1beta2/gapic_metadata.json |    156 [31m-[m
 .../ai/generativelanguage_v1beta2/gapic_version.py |     16 [31m-[m
 .../google/ai/generativelanguage_v1beta2/py.typed  |      2 [31m-[m
 .../services/__init__.py                           |     15 [31m-[m
 .../services/__pycache__/__init__.cpython-312.pyc  |    Bin [31m207[m -> [32m0[m bytes
 .../services/discuss_service/__init__.py           |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m374[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m26434[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m42026[m -> [32m0[m bytes
 .../services/discuss_service/async_client.py       |    628 [31m-[m
 .../services/discuss_service/client.py             |   1016 [31m-[m
 .../discuss_service/transports/__init__.py         |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m791[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7516[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m16882[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m19261[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m22373[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m8687[m -> [32m0[m bytes
 .../services/discuss_service/transports/base.py    |    199 [31m-[m
 .../services/discuss_service/transports/grpc.py    |    394 [31m-[m
 .../discuss_service/transports/grpc_asyncio.py     |    439 [31m-[m
 .../services/discuss_service/transports/rest.py    |    578 [31m-[m
 .../discuss_service/transports/rest_base.py        |    205 [31m-[m
 .../services/model_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m368[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m22975[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m38561[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m9999[m -> [32m0[m bytes
 .../services/model_service/async_client.py         |    547 [31m-[m
 .../services/model_service/client.py               |    934 [31m-[m
 .../services/model_service/pagers.py               |    197 [31m-[m
 .../services/model_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m779[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7435[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m16524[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m18897[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m21161[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m7422[m -> [32m0[m bytes
 .../services/model_service/transports/base.py      |    195 [31m-[m
 .../services/model_service/transports/grpc.py      |    382 [31m-[m
 .../model_service/transports/grpc_asyncio.py       |    431 [31m-[m
 .../services/model_service/transports/rest.py      |    542 [31m-[m
 .../services/model_service/transports/rest_base.py |    170 [31m-[m
 .../services/text_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m365[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m26709[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m42225[m -> [32m0[m bytes
 .../services/text_service/async_client.py          |    636 [31m-[m
 .../services/text_service/client.py                |   1023 [31m-[m
 .../services/text_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m773[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7436[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m16702[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m19071[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m21557[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m8495[m -> [32m0[m bytes
 .../services/text_service/transports/base.py       |    198 [31m-[m
 .../services/text_service/transports/grpc.py       |    390 [31m-[m
 .../text_service/transports/grpc_asyncio.py        |    437 [31m-[m
 .../services/text_service/transports/rest.py       |    563 [31m-[m
 .../services/text_service/transports/rest_base.py  |    205 [31m-[m
 .../generativelanguage_v1beta2/types/__init__.py   |     71 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1192[m -> [32m0[m bytes
 .../types/__pycache__/citation.cpython-312.pyc     |    Bin [31m3178[m -> [32m0[m bytes
 .../__pycache__/discuss_service.cpython-312.pyc    |    Bin [31m13274[m -> [32m0[m bytes
 .../types/__pycache__/model.cpython-312.pyc        |    Bin [31m5130[m -> [32m0[m bytes
 .../__pycache__/model_service.cpython-312.pyc      |    Bin [31m3838[m -> [32m0[m bytes
 .../types/__pycache__/safety.cpython-312.pyc       |    Bin [31m9284[m -> [32m0[m bytes
 .../types/__pycache__/text_service.cpython-312.pyc |    Bin [31m12815[m -> [32m0[m bytes
 .../generativelanguage_v1beta2/types/citation.py   |    101 [31m-[m
 .../types/discuss_service.py                       |    356 [31m-[m
 .../ai/generativelanguage_v1beta2/types/model.py   |    155 [31m-[m
 .../types/model_service.py                         |    113 [31m-[m
 .../ai/generativelanguage_v1beta2/types/safety.py  |    249 [31m-[m
 .../types/text_service.py                          |    331 [31m-[m
 .../ai/generativelanguage_v1beta3/__init__.py      |    155 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m2962[m -> [32m0[m bytes
 .../__pycache__/gapic_version.cpython-312.pyc      |    Bin [31m232[m -> [32m0[m bytes
 .../generativelanguage_v1beta3/gapic_metadata.json |    370 [31m-[m
 .../ai/generativelanguage_v1beta3/gapic_version.py |     16 [31m-[m
 .../google/ai/generativelanguage_v1beta3/py.typed  |      2 [31m-[m
 .../services/__init__.py                           |     15 [31m-[m
 .../services/__pycache__/__init__.cpython-312.pyc  |    Bin [31m207[m -> [32m0[m bytes
 .../services/discuss_service/__init__.py           |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m374[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m26491[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m42084[m -> [32m0[m bytes
 .../services/discuss_service/async_client.py       |    630 [31m-[m
 .../services/discuss_service/client.py             |   1018 [31m-[m
 .../discuss_service/transports/__init__.py         |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m791[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m7079[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m16940[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m18815[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m22431[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m8745[m -> [32m0[m bytes
 .../services/discuss_service/transports/base.py    |    182 [31m-[m
 .../services/discuss_service/transports/grpc.py    |    395 [31m-[m
 .../discuss_service/transports/grpc_asyncio.py     |    422 [31m-[m
 .../services/discuss_service/transports/rest.py    |    579 [31m-[m
 .../discuss_service/transports/rest_base.py        |    206 [31m-[m
 .../services/model_service/__init__.py             |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m368[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m45920[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m61092[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m18308[m -> [32m0[m bytes
 .../services/model_service/async_client.py         |   1156 [31m-[m
 .../services/model_service/client.py               |   1541 [31m-[m
 .../services/model_service/pagers.py               |    353 [31m-[m
 .../services/model_service/transports/__init__.py  |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m779[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m10130[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m23081[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m25766[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m53288[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m16996[m -> [32m0[m bytes
 .../services/model_service/transports/base.py      |    259 [31m-[m
 .../services/model_service/transports/grpc.py      |    540 [31m-[m
 .../model_service/transports/grpc_asyncio.py       |    603 [31m-[m
 .../services/model_service/transports/rest.py      |   1462 [31m-[m
 .../services/model_service/transports/rest_base.py |    416 [31m-[m
 .../services/permission_service/__init__.py        |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m383[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m41726[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m57384[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m10191[m -> [32m0[m bytes
 .../services/permission_service/async_client.py    |   1040 [31m-[m
 .../services/permission_service/client.py          |   1433 [31m-[m
 .../services/permission_service/pagers.py          |    197 [31m-[m
 .../permission_service/transports/__init__.py      |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m809[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m9387[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m21308[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m23838[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m48779[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m16859[m -> [32m0[m bytes
 .../services/permission_service/transports/base.py |    241 [31m-[m
 .../services/permission_service/transports/grpc.py |    505 [31m-[m
 .../permission_service/transports/grpc_asyncio.py  |    558 [31m-[m
 .../services/permission_service/transports/rest.py |   1340 [31m-[m
 .../permission_service/transports/rest_base.py     |    409 [31m-[m
 .../services/text_service/__init__.py              |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m365[m -> [32m0[m bytes
 .../__pycache__/async_client.cpython-312.pyc       |    Bin [31m36588[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m51655[m -> [32m0[m bytes
 .../services/text_service/async_client.py          |    897 [31m-[m
 .../services/text_service/client.py                |   1278 [31m-[m
 .../services/text_service/transports/__init__.py   |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m773[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m8112[m -> [32m0[m bytes
 .../transports/__pycache__/grpc.cpython-312.pyc    |    Bin [31m19069[m -> [32m0[m bytes
 .../__pycache__/grpc_asyncio.cpython-312.pyc       |    Bin [31m21256[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m34909[m -> [32m0[m bytes
 .../__pycache__/rest_base.cpython-312.pyc          |    Bin [31m13050[m -> [32m0[m bytes
 .../services/text_service/transports/base.py       |    215 [31m-[m
 .../services/text_service/transports/grpc.py       |    449 [31m-[m
 .../text_service/transports/grpc_asyncio.py        |    490 [31m-[m
 .../services/text_service/transports/rest.py       |    959 [31m-[m
 .../services/text_service/transports/rest_base.py  |    325 [31m-[m
 .../generativelanguage_v1beta3/types/__init__.py   |    135 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m2302[m -> [32m0[m bytes
 .../types/__pycache__/citation.cpython-312.pyc     |    Bin [31m3178[m -> [32m0[m bytes
 .../__pycache__/discuss_service.cpython-312.pyc    |    Bin [31m13274[m -> [32m0[m bytes
 .../types/__pycache__/model.cpython-312.pyc        |    Bin [31m5130[m -> [32m0[m bytes
 .../__pycache__/model_service.cpython-312.pyc      |    Bin [31m11300[m -> [32m0[m bytes
 .../types/__pycache__/permission.cpython-312.pyc   |    Bin [31m4898[m -> [32m0[m bytes
 .../__pycache__/permission_service.cpython-312.pyc |    Bin [31m7881[m -> [32m0[m bytes
 .../types/__pycache__/safety.cpython-312.pyc       |    Bin [31m9383[m -> [32m0[m bytes
 .../types/__pycache__/text_service.cpython-312.pyc |    Bin [31m16439[m -> [32m0[m bytes
 .../types/__pycache__/tuned_model.cpython-312.pyc  |    Bin [31m15235[m -> [32m0[m bytes
 .../generativelanguage_v1beta3/types/citation.py   |    101 [31m-[m
 .../types/discuss_service.py                       |    356 [31m-[m
 .../ai/generativelanguage_v1beta3/types/model.py   |    155 [31m-[m
 .../types/model_service.py                         |    309 [31m-[m
 .../generativelanguage_v1beta3/types/permission.py |    140 [31m-[m
 .../types/permission_service.py                    |    218 [31m-[m
 .../ai/generativelanguage_v1beta3/types/safety.py  |    252 [31m-[m
 .../types/text_service.py                          |    429 [31m-[m
 .../types/tuned_model.py                           |    413 [31m-[m
 .../__pycache__/annotations_pb2.cpython-312.pyc    |    Bin [31m1682[m -> [32m0[m bytes
 .../api/__pycache__/auth_pb2.cpython-312.pyc       |    Bin [31m2614[m -> [32m0[m bytes
 .../api/__pycache__/backend_pb2.cpython-312.pyc    |    Bin [31m2710[m -> [32m0[m bytes
 .../api/__pycache__/billing_pb2.cpython-312.pyc    |    Bin [31m1757[m -> [32m0[m bytes
 .../api/__pycache__/client_pb2.cpython-312.pyc     |    Bin [31m7784[m -> [32m0[m bytes
 .../__pycache__/config_change_pb2.cpython-312.pyc  |    Bin [31m1979[m -> [32m0[m bytes
 .../api/__pycache__/consumer_pb2.cpython-312.pyc   |    Bin [31m1930[m -> [32m0[m bytes
 .../api/__pycache__/context_pb2.cpython-312.pyc    |    Bin [31m1790[m -> [32m0[m bytes
 .../api/__pycache__/control_pb2.cpython-312.pyc    |    Bin [31m1692[m -> [32m0[m bytes
 .../__pycache__/distribution_pb2.cpython-312.pyc   |    Bin [31m3251[m -> [32m0[m bytes
 .../__pycache__/documentation_pb2.cpython-312.pyc  |    Bin [31m2087[m -> [32m0[m bytes
 .../api/__pycache__/endpoint_pb2.cpython-312.pyc   |    Bin [31m1590[m -> [32m0[m bytes
 .../__pycache__/error_reason_pb2.cpython-312.pyc   |    Bin [31m2490[m -> [32m0[m bytes
 .../__pycache__/field_behavior_pb2.cpython-312.pyc |    Bin [31m2020[m -> [32m0[m bytes
 .../api/__pycache__/field_info_pb2.cpython-312.pyc |    Bin [31m2127[m -> [32m0[m bytes
 .../api/__pycache__/http_pb2.cpython-312.pyc       |    Bin [31m2059[m -> [32m0[m bytes
 .../api/__pycache__/httpbody_pb2.cpython-312.pyc   |    Bin [31m1674[m -> [32m0[m bytes
 .../api/__pycache__/label_pb2.cpython-312.pyc      |    Bin [31m1733[m -> [32m0[m bytes
 .../__pycache__/launch_stage_pb2.cpython-312.pyc   |    Bin [31m1632[m -> [32m0[m bytes
 .../google/api/__pycache__/log_pb2.cpython-312.pyc |    Bin [31m1713[m -> [32m0[m bytes
 .../api/__pycache__/logging_pb2.cpython-312.pyc    |    Bin [31m1825[m -> [32m0[m bytes
 .../api/__pycache__/metric_pb2.cpython-312.pyc     |    Bin [31m3936[m -> [32m0[m bytes
 .../monitored_resource_pb2.cpython-312.pyc         |    Bin [31m3011[m -> [32m0[m bytes
 .../api/__pycache__/monitoring_pb2.cpython-312.pyc |    Bin [31m1875[m -> [32m0[m bytes
 .../api/__pycache__/policy_pb2.cpython-312.pyc     |    Bin [31m2044[m -> [32m0[m bytes
 .../api/__pycache__/quota_pb2.cpython-312.pyc      |    Bin [31m2538[m -> [32m0[m bytes
 .../api/__pycache__/resource_pb2.cpython-312.pyc   |    Bin [31m2625[m -> [32m0[m bytes
 .../api/__pycache__/routing_pb2.cpython-312.pyc    |    Bin [31m1920[m -> [32m0[m bytes
 .../api/__pycache__/service_pb2.cpython-312.pyc    |    Bin [31m4595[m -> [32m0[m bytes
 .../__pycache__/source_info_pb2.cpython-312.pyc    |    Bin [31m1682[m -> [32m0[m bytes
 .../system_parameter_pb2.cpython-312.pyc           |    Bin [31m2001[m -> [32m0[m bytes
 .../api/__pycache__/usage_pb2.cpython-312.pyc      |    Bin [31m1784[m -> [32m0[m bytes
 .../api/__pycache__/visibility_pb2.cpython-312.pyc |    Bin [31m2375[m -> [32m0[m bytes
 .../Lib/site-packages/google/api/annotations.proto |     31 [31m-[m
 .../site-packages/google/api/annotations_pb2.py    |     48 [31m-[m
 .../site-packages/google/api/annotations_pb2.pyi   |     23 [31m-[m
 .../venv/Lib/site-packages/google/api/auth.proto   |    237 [31m-[m
 .../venv/Lib/site-packages/google/api/auth_pb2.py  |     55 [31m-[m
 .../venv/Lib/site-packages/google/api/auth_pb2.pyi |    120 [31m-[m
 .../Lib/site-packages/google/api/backend.proto     |    185 [31m-[m
 .../Lib/site-packages/google/api/backend_pb2.py    |     59 [31m-[m
 .../Lib/site-packages/google/api/backend_pb2.pyi   |    102 [31m-[m
 .../Lib/site-packages/google/api/billing.proto     |     77 [31m-[m
 .../Lib/site-packages/google/api/billing_pb2.py    |     47 [31m-[m
 .../Lib/site-packages/google/api/billing_pb2.pyi   |     50 [31m-[m
 .../venv/Lib/site-packages/google/api/client.proto |    486 [31m-[m
 .../Lib/site-packages/google/api/client_pb2.py     |    103 [31m-[m
 .../Lib/site-packages/google/api/client_pb2.pyi    |    404 [31m-[m
 .../site-packages/google/api/config_change.proto   |     84 [31m-[m
 .../site-packages/google/api/config_change_pb2.py  |     51 [31m-[m
 .../site-packages/google/api/config_change_pb2.pyi |     65 [31m-[m
 .../Lib/site-packages/google/api/consumer.proto    |     82 [31m-[m
 .../Lib/site-packages/google/api/consumer_pb2.py   |     49 [31m-[m
 .../Lib/site-packages/google/api/consumer_pb2.pyi  |     62 [31m-[m
 .../Lib/site-packages/google/api/context.proto     |     92 [31m-[m
 .../Lib/site-packages/google/api/context_pb2.py    |     47 [31m-[m
 .../Lib/site-packages/google/api/context_pb2.pyi   |     60 [31m-[m
 .../Lib/site-packages/google/api/control.proto     |     41 [31m-[m
 .../Lib/site-packages/google/api/control_pb2.py    |     47 [31m-[m
 .../Lib/site-packages/google/api/control_pb2.pyi   |     42 [31m-[m
 .../site-packages/google/api/distribution.proto    |    213 [31m-[m
 .../site-packages/google/api/distribution_pb2.py   |     62 [31m-[m
 .../site-packages/google/api/distribution_pb2.pyi  |    144 [31m-[m
 .../site-packages/google/api/documentation.proto   |    168 [31m-[m
 .../site-packages/google/api/documentation_pb2.py  |     51 [31m-[m
 .../site-packages/google/api/documentation_pb2.pyi |     86 [31m-[m
 .../Lib/site-packages/google/api/endpoint.proto    |     69 [31m-[m
 .../Lib/site-packages/google/api/endpoint_pb2.py   |     45 [31m-[m
 .../Lib/site-packages/google/api/endpoint_pb2.pyi  |     41 [31m-[m
 .../site-packages/google/api/error_reason.proto    |    622 [31m-[m
 .../site-packages/google/api/error_reason_pb2.py   |     47 [31m-[m
 .../site-packages/google/api/error_reason_pb2.pyi  |     90 [31m-[m
 .../site-packages/google/api/field_behavior.proto  |    104 [31m-[m
 .../site-packages/google/api/field_behavior_pb2.py |     51 [31m-[m
 .../google/api/field_behavior_pb2.pyi              |     45 [31m-[m
 .../Lib/site-packages/google/api/field_info.proto  |    106 [31m-[m
 .../Lib/site-packages/google/api/field_info_pb2.py |     53 [31m-[m
 .../site-packages/google/api/field_info_pb2.pyi    |     60 [31m-[m
 .../venv/Lib/site-packages/google/api/http.proto   |    370 [31m-[m
 .../venv/Lib/site-packages/google/api/http_pb2.py  |     49 [31m-[m
 .../venv/Lib/site-packages/google/api/http_pb2.pyi |     94 [31m-[m
 .../Lib/site-packages/google/api/httpbody.proto    |     80 [31m-[m
 .../Lib/site-packages/google/api/httpbody_pb2.py   |     47 [31m-[m
 .../Lib/site-packages/google/api/httpbody_pb2.pyi  |     41 [31m-[m
 .../venv/Lib/site-packages/google/api/label.proto  |     47 [31m-[m
 .../venv/Lib/site-packages/google/api/label_pb2.py |     47 [31m-[m
 .../Lib/site-packages/google/api/label_pb2.pyi     |     47 [31m-[m
 .../site-packages/google/api/launch_stage.proto    |     72 [31m-[m
 .../site-packages/google/api/launch_stage_pb2.py   |     47 [31m-[m
 .../site-packages/google/api/launch_stage_pb2.pyi  |     40 [31m-[m
 .../venv/Lib/site-packages/google/api/log.proto    |     54 [31m-[m
 .../venv/Lib/site-packages/google/api/log_pb2.py   |     47 [31m-[m
 .../venv/Lib/site-packages/google/api/log_pb2.pyi  |     46 [31m-[m
 .../Lib/site-packages/google/api/logging.proto     |     81 [31m-[m
 .../Lib/site-packages/google/api/logging_pb2.py    |     47 [31m-[m
 .../Lib/site-packages/google/api/logging_pb2.pyi   |     57 [31m-[m
 .../venv/Lib/site-packages/google/api/metric.proto |    287 [31m-[m
 .../Lib/site-packages/google/api/metric_pb2.py     |     73 [31m-[m
 .../Lib/site-packages/google/api/metric_pb2.pyi    |    185 [31m-[m
 .../google/api/monitored_resource.proto            |    129 [31m-[m
 .../google/api/monitored_resource_pb2.py           |     65 [31m-[m
 .../google/api/monitored_resource_pb2.pyi          |    103 [31m-[m
 .../Lib/site-packages/google/api/monitoring.proto  |    107 [31m-[m
 .../Lib/site-packages/google/api/monitoring_pb2.py |     49 [31m-[m
 .../site-packages/google/api/monitoring_pb2.pyi    |     57 [31m-[m
 .../venv/Lib/site-packages/google/api/policy.proto |     82 [31m-[m
 .../Lib/site-packages/google/api/policy_pb2.py     |     49 [31m-[m
 .../Lib/site-packages/google/api/policy_pb2.pyi    |     57 [31m-[m
 .../venv/Lib/site-packages/google/api/quota.proto  |    184 [31m-[m
 .../venv/Lib/site-packages/google/api/quota_pb2.py |     57 [31m-[m
 .../Lib/site-packages/google/api/quota_pb2.pyi     |    116 [31m-[m
 .../Lib/site-packages/google/api/resource.proto    |    242 [31m-[m
 .../Lib/site-packages/google/api/resource_pb2.py   |     53 [31m-[m
 .../Lib/site-packages/google/api/resource_pb2.pyi  |     93 [31m-[m
 .../Lib/site-packages/google/api/routing.proto     |    461 [31m-[m
 .../Lib/site-packages/google/api/routing_pb2.py    |     49 [31m-[m
 .../Lib/site-packages/google/api/routing_pb2.pyi   |     49 [31m-[m
 .../Lib/site-packages/google/api/service.proto     |    191 [31m-[m
 .../Lib/site-packages/google/api/service_pb2.py    |     69 [31m-[m
 .../Lib/site-packages/google/api/service_pb2.pyi   |    169 [31m-[m
 .../Lib/site-packages/google/api/source_info.proto |     31 [31m-[m
 .../site-packages/google/api/source_info_pb2.py    |     49 [31m-[m
 .../site-packages/google/api/source_info_pb2.pyi   |     34 [31m-[m
 .../google/api/system_parameter.proto              |     96 [31m-[m
 .../google/api/system_parameter_pb2.py             |     51 [31m-[m
 .../google/api/system_parameter_pb2.pyi            |     60 [31m-[m
 .../venv/Lib/site-packages/google/api/usage.proto  |     96 [31m-[m
 .../venv/Lib/site-packages/google/api/usage_pb2.py |     47 [31m-[m
 .../Lib/site-packages/google/api/usage_pb2.pyi     |     55 [31m-[m
 .../Lib/site-packages/google/api/visibility.proto  |    112 [31m-[m
 .../Lib/site-packages/google/api/visibility_pb2.py |     51 [31m-[m
 .../site-packages/google/api/visibility_pb2.pyi    |     56 [31m-[m
 .../Lib/site-packages/google/api_core/__init__.py  |     40 [31m-[m
 .../api_core/__pycache__/__init__.cpython-312.pyc  |    Bin [31m852[m -> [32m0[m bytes
 .../_python_package_support.cpython-312.pyc        |    Bin [31m7934[m -> [32m0[m bytes
 .../_python_version_support.cpython-312.pyc        |    Bin [31m10577[m -> [32m0[m bytes
 .../_rest_streaming_base.cpython-312.pyc           |    Bin [31m4832[m -> [32m0[m bytes
 .../api_core/__pycache__/bidi.cpython-312.pyc      |    Bin [31m28521[m -> [32m0[m bytes
 .../__pycache__/bidi_async.cpython-312.pyc         |    Bin [31m8807[m -> [32m0[m bytes
 .../api_core/__pycache__/bidi_base.cpython-312.pyc |    Bin [31m3566[m -> [32m0[m bytes
 .../__pycache__/client_info.cpython-312.pyc        |    Bin [31m3872[m -> [32m0[m bytes
 .../__pycache__/client_logging.cpython-312.pyc     |    Bin [31m5087[m -> [32m0[m bytes
 .../__pycache__/client_options.cpython-312.pyc     |    Bin [31m6986[m -> [32m0[m bytes
 .../__pycache__/datetime_helpers.cpython-312.pyc   |    Bin [31m11544[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m28715[m -> [32m0[m bytes
 .../__pycache__/extended_operation.cpython-312.pyc |    Bin [31m8869[m -> [32m0[m bytes
 .../__pycache__/general_helpers.cpython-312.pyc    |    Bin [31m1837[m -> [32m0[m bytes
 .../__pycache__/grpc_helpers.cpython-312.pyc       |    Bin [31m24795[m -> [32m0[m bytes
 .../__pycache__/grpc_helpers_async.cpython-312.pyc |    Bin [31m17823[m -> [32m0[m bytes
 .../api_core/__pycache__/iam.cpython-312.pyc       |    Bin [31m15510[m -> [32m0[m bytes
 .../api_core/__pycache__/operation.cpython-312.pyc |    Bin [31m14618[m -> [32m0[m bytes
 .../__pycache__/operation_async.cpython-312.pyc    |    Bin [31m9257[m -> [32m0[m bytes
 .../__pycache__/page_iterator.cpython-312.pyc      |    Bin [31m21902[m -> [32m0[m bytes
 .../page_iterator_async.cpython-312.pyc            |    Bin [31m10716[m -> [32m0[m bytes
 .../__pycache__/path_template.cpython-312.pyc      |    Bin [31m12000[m -> [32m0[m bytes
 .../__pycache__/protobuf_helpers.cpython-312.pyc   |    Bin [31m12903[m -> [32m0[m bytes
 .../__pycache__/rest_helpers.cpython-312.pyc       |    Bin [31m4169[m -> [32m0[m bytes
 .../__pycache__/rest_streaming.cpython-312.pyc     |    Bin [31m2801[m -> [32m0[m bytes
 .../rest_streaming_async.cpython-312.pyc           |    Bin [31m4074[m -> [32m0[m bytes
 .../__pycache__/retry_async.cpython-312.pyc        |    Bin [31m600[m -> [32m0[m bytes
 .../api_core/__pycache__/timeout.cpython-312.pyc   |    Bin [31m10232[m -> [32m0[m bytes
 .../api_core/__pycache__/universe.cpython-312.pyc  |    Bin [31m3134[m -> [32m0[m bytes
 .../api_core/__pycache__/version.cpython-312.pyc   |    Bin [31m205[m -> [32m0[m bytes
 .../__pycache__/version_header.cpython-312.pyc     |    Bin [31m707[m -> [32m0[m bytes
 .../google/api_core/_python_package_support.py     |    234 [31m-[m
 .../google/api_core/_python_version_support.py     |    269 [31m-[m
 .../google/api_core/_rest_streaming_base.py        |    118 [31m-[m
 .../venv/Lib/site-packages/google/api_core/bidi.py |    735 [31m-[m
 .../site-packages/google/api_core/bidi_async.py    |    244 [31m-[m
 .../Lib/site-packages/google/api_core/bidi_base.py |     88 [31m-[m
 .../site-packages/google/api_core/client_info.py   |    114 [31m-[m
 .../google/api_core/client_logging.py              |    144 [31m-[m
 .../google/api_core/client_options.py              |    160 [31m-[m
 .../google/api_core/datetime_helpers.py            |    298 [31m-[m
 .../site-packages/google/api_core/exceptions.py    |    670 [31m-[m
 .../google/api_core/extended_operation.py          |    225 [31m-[m
 .../google/api_core/future/__init__.py             |     19 [31m-[m
 .../future/__pycache__/__init__.cpython-312.pyc    |    Bin [31m341[m -> [32m0[m bytes
 .../future/__pycache__/_helpers.cpython-312.pyc    |    Bin [31m1112[m -> [32m0[m bytes
 .../__pycache__/async_future.cpython-312.pyc       |    Bin [31m7016[m -> [32m0[m bytes
 .../future/__pycache__/base.cpython-312.pyc        |    Bin [31m2374[m -> [32m0[m bytes
 .../future/__pycache__/polling.cpython-312.pyc     |    Bin [31m14830[m -> [32m0[m bytes
 .../google/api_core/future/_helpers.py             |     39 [31m-[m
 .../google/api_core/future/async_future.py         |    162 [31m-[m
 .../site-packages/google/api_core/future/base.py   |     64 [31m-[m
 .../google/api_core/future/polling.py              |    323 [31m-[m
 .../google/api_core/gapic_v1/__init__.py           |     29 [31m-[m
 .../gapic_v1/__pycache__/__init__.cpython-312.pyc  |    Bin [31m477[m -> [32m0[m bytes
 .../__pycache__/client_info.cpython-312.pyc        |    Bin [31m2353[m -> [32m0[m bytes
 .../gapic_v1/__pycache__/config.cpython-312.pyc    |    Bin [31m6194[m -> [32m0[m bytes
 .../__pycache__/config_async.cpython-312.pyc       |    Bin [31m1493[m -> [32m0[m bytes
 .../gapic_v1/__pycache__/method.cpython-312.pyc    |    Bin [31m9216[m -> [32m0[m bytes
 .../__pycache__/method_async.cpython-312.pyc       |    Bin [31m1706[m -> [32m0[m bytes
 .../__pycache__/routing_header.cpython-312.pyc     |    Bin [31m2922[m -> [32m0[m bytes
 .../google/api_core/gapic_v1/client_info.py        |     58 [31m-[m
 .../google/api_core/gapic_v1/config.py             |    175 [31m-[m
 .../google/api_core/gapic_v1/config_async.py       |     42 [31m-[m
 .../google/api_core/gapic_v1/method.py             |    253 [31m-[m
 .../google/api_core/gapic_v1/method_async.py       |     59 [31m-[m
 .../google/api_core/gapic_v1/routing_header.py     |     87 [31m-[m
 .../google/api_core/general_helpers.py             |     52 [31m-[m
 .../site-packages/google/api_core/grpc_helpers.py  |    649 [31m-[m
 .../google/api_core/grpc_helpers_async.py          |    348 [31m-[m
 .../venv/Lib/site-packages/google/api_core/iam.py  |    427 [31m-[m
 .../Lib/site-packages/google/api_core/operation.py |    365 [31m-[m
 .../google/api_core/operation_async.py             |    225 [31m-[m
 .../google/api_core/operations_v1/__init__.py      |     40 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1057[m -> [32m0[m bytes
 ...abstract_operations_base_client.cpython-312.pyc |    Bin [31m15945[m -> [32m0[m bytes
 .../abstract_operations_client.cpython-312.pyc     |    Bin [31m15964[m -> [32m0[m bytes
 .../operations_async_client.cpython-312.pyc        |    Bin [31m14945[m -> [32m0[m bytes
 .../__pycache__/operations_client.cpython-312.pyc  |    Bin [31m15304[m -> [32m0[m bytes
 .../operations_client_config.cpython-312.pyc       |    Bin [31m1028[m -> [32m0[m bytes
 .../operations_rest_client_async.cpython-312.pyc   |    Bin [31m13669[m -> [32m0[m bytes
 .../__pycache__/pagers.cpython-312.pyc             |    Bin [31m3046[m -> [32m0[m bytes
 .../__pycache__/pagers_async.cpython-312.pyc       |    Bin [31m3376[m -> [32m0[m bytes
 .../__pycache__/pagers_base.cpython-312.pyc        |    Bin [31m2997[m -> [32m0[m bytes
 .../abstract_operations_base_client.py             |    370 [31m-[m
 .../operations_v1/abstract_operations_client.py    |    387 [31m-[m
 .../operations_v1/operations_async_client.py       |    364 [31m-[m
 .../api_core/operations_v1/operations_client.py    |    378 [31m-[m
 .../operations_v1/operations_client_config.py      |     60 [31m-[m
 .../operations_v1/operations_rest_client_async.py  |    345 [31m-[m
 .../google/api_core/operations_v1/pagers.py        |     67 [31m-[m
 .../google/api_core/operations_v1/pagers_async.py  |     71 [31m-[m
 .../google/api_core/operations_v1/pagers_base.py   |     73 [31m-[m
 .../api_core/operations_v1/transports/__init__.py  |     39 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m880[m -> [32m0[m bytes
 .../transports/__pycache__/base.cpython-312.pyc    |    Bin [31m11146[m -> [32m0[m bytes
 .../transports/__pycache__/rest.cpython-312.pyc    |    Bin [31m19653[m -> [32m0[m bytes
 .../__pycache__/rest_asyncio.cpython-312.pyc       |    Bin [31m22560[m -> [32m0[m bytes
 .../api_core/operations_v1/transports/base.py      |    300 [31m-[m
 .../api_core/operations_v1/transports/rest.py      |    492 [31m-[m
 .../operations_v1/transports/rest_asyncio.py       |    581 [31m-[m
 .../site-packages/google/api_core/page_iterator.py |    571 [31m-[m
 .../google/api_core/page_iterator_async.py         |    285 [31m-[m
 .../site-packages/google/api_core/path_template.py |    346 [31m-[m
 .../google/api_core/protobuf_helpers.py            |    371 [31m-[m
 .../Lib/site-packages/google/api_core/py.typed     |      2 [31m-[m
 .../site-packages/google/api_core/rest_helpers.py  |    109 [31m-[m
 .../google/api_core/rest_streaming.py              |     66 [31m-[m
 .../google/api_core/rest_streaming_async.py        |     89 [31m-[m
 .../google/api_core/retry/__init__.py              |     52 [31m-[m
 .../retry/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1089[m -> [32m0[m bytes
 .../retry/__pycache__/retry_base.cpython-312.pyc   |    Bin [31m13302[m -> [32m0[m bytes
 .../__pycache__/retry_streaming.cpython-312.pyc    |    Bin [31m10436[m -> [32m0[m bytes
 .../retry_streaming_async.cpython-312.pyc          |    Bin [31m13293[m -> [32m0[m bytes
 .../retry/__pycache__/retry_unary.cpython-312.pyc  |    Bin [31m13216[m -> [32m0[m bytes
 .../__pycache__/retry_unary_async.cpython-312.pyc  |    Bin [31m9259[m -> [32m0[m bytes
 .../google/api_core/retry/retry_base.py            |    370 [31m-[m
 .../google/api_core/retry/retry_streaming.py       |    264 [31m-[m
 .../google/api_core/retry/retry_streaming_async.py |    328 [31m-[m
 .../google/api_core/retry/retry_unary.py           |    302 [31m-[m
 .../google/api_core/retry/retry_unary_async.py     |    239 [31m-[m
 .../site-packages/google/api_core/retry_async.py   |     34 [31m-[m
 .../Lib/site-packages/google/api_core/timeout.py   |    294 [31m-[m
 .../Lib/site-packages/google/api_core/universe.py  |     82 [31m-[m
 .../Lib/site-packages/google/api_core/version.py   |     15 [31m-[m
 .../google/api_core/version_header.py              |     29 [31m-[m
 .../venv/Lib/site-packages/google/auth/__init__.py |     53 [31m-[m
 .../auth/__pycache__/__init__.cpython-312.pyc      |    Bin [31m1473[m -> [32m0[m bytes
 .../_agent_identity_utils.cpython-312.pyc          |    Bin [31m10123[m -> [32m0[m bytes
 .../auth/__pycache__/_cloud_sdk.cpython-312.pyc    |    Bin [31m5062[m -> [32m0[m bytes
 .../auth/__pycache__/_constants.cpython-312.pyc    |    Bin [31m753[m -> [32m0[m bytes
 .../__pycache__/_credentials_async.cpython-312.pyc |    Bin [31m7446[m -> [32m0[m bytes
 .../__pycache__/_credentials_base.cpython-312.pyc  |    Bin [31m2841[m -> [32m0[m bytes
 .../auth/__pycache__/_default.cpython-312.pyc      |    Bin [31m30298[m -> [32m0[m bytes
 .../__pycache__/_default_async.cpython-312.pyc     |    Bin [31m11678[m -> [32m0[m bytes
 .../_exponential_backoff.cpython-312.pyc           |    Bin [31m6360[m -> [32m0[m bytes
 .../auth/__pycache__/_helpers.cpython-312.pyc      |    Bin [31m19026[m -> [32m0[m bytes
 .../auth/__pycache__/_jwt_async.cpython-312.pyc    |    Bin [31m6089[m -> [32m0[m bytes
 .../auth/__pycache__/_oauth2client.cpython-312.pyc |    Bin [31m6471[m -> [32m0[m bytes
 .../__pycache__/_refresh_worker.cpython-312.pyc    |    Bin [31m4618[m -> [32m0[m bytes
 .../_service_account_info.cpython-312.pyc          |    Bin [31m2899[m -> [32m0[m bytes
 .../auth/__pycache__/api_key.cpython-312.pyc       |    Bin [31m3087[m -> [32m0[m bytes
 .../auth/__pycache__/app_engine.cpython-312.pyc    |    Bin [31m7392[m -> [32m0[m bytes
 .../google/auth/__pycache__/aws.cpython-312.pyc    |    Bin [31m32879[m -> [32m0[m bytes
 .../auth/__pycache__/credentials.cpython-312.pyc   |    Bin [31m28268[m -> [32m0[m bytes
 .../auth/__pycache__/downscoped.cpython-312.pyc    |    Bin [31m23845[m -> [32m0[m bytes
 .../__pycache__/environment_vars.cpython-312.pyc   |    Bin [31m1180[m -> [32m0[m bytes
 .../auth/__pycache__/exceptions.cpython-312.pyc    |    Bin [31m5279[m -> [32m0[m bytes
 .../__pycache__/external_account.cpython-312.pyc   |    Bin [31m30642[m -> [32m0[m bytes
 ...xternal_account_authorized_user.cpython-312.pyc |    Bin [31m20645[m -> [32m0[m bytes
 .../google/auth/__pycache__/iam.cpython-312.pyc    |    Bin [31m5538[m -> [32m0[m bytes
 .../auth/__pycache__/identity_pool.cpython-312.pyc |    Bin [31m26065[m -> [32m0[m bytes
 .../impersonated_credentials.cpython-312.pyc       |    Bin [31m29937[m -> [32m0[m bytes
 .../google/auth/__pycache__/jwt.cpython-312.pyc    |    Bin [31m34766[m -> [32m0[m bytes
 .../auth/__pycache__/metrics.cpython-312.pyc       |    Bin [31m4749[m -> [32m0[m bytes
 .../auth/__pycache__/pluggable.cpython-312.pyc     |    Bin [31m18844[m -> [32m0[m bytes
 .../auth/__pycache__/version.cpython-312.pyc       |    Bin [31m201[m -> [32m0[m bytes
 .../google/auth/_agent_identity_utils.py           |    281 [31m-[m
 .../Lib/site-packages/google/auth/_cloud_sdk.py    |    153 [31m-[m
 .../Lib/site-packages/google/auth/_constants.py    |      5 [31m-[m
 .../google/auth/_credentials_async.py              |    171 [31m-[m
 .../site-packages/google/auth/_credentials_base.py |     75 [31m-[m
 .../venv/Lib/site-packages/google/auth/_default.py |    739 [31m-[m
 .../site-packages/google/auth/_default_async.py    |    288 [31m-[m
 .../google/auth/_exponential_backoff.py            |    164 [31m-[m
 .../venv/Lib/site-packages/google/auth/_helpers.py |    554 [31m-[m
 .../Lib/site-packages/google/auth/_jwt_async.py    |    164 [31m-[m
 .../Lib/site-packages/google/auth/_oauth2client.py |    167 [31m-[m
 .../site-packages/google/auth/_refresh_worker.py   |    109 [31m-[m
 .../google/auth/_service_account_info.py           |     80 [31m-[m
 .../Lib/site-packages/google/auth/aio/__init__.py  |     25 [31m-[m
 .../auth/aio/__pycache__/__init__.cpython-312.pyc  |    Bin [31m552[m -> [32m0[m bytes
 .../auth/aio/__pycache__/_helpers.cpython-312.pyc  |    Bin [31m1795[m -> [32m0[m bytes
 .../aio/__pycache__/credentials.cpython-312.pyc    |    Bin [31m6434[m -> [32m0[m bytes
 .../Lib/site-packages/google/auth/aio/_helpers.py  |     62 [31m-[m
 .../site-packages/google/auth/aio/credentials.py   |    143 [31m-[m
 .../google/auth/aio/transport/__init__.py          |    144 [31m-[m
 .../transport/__pycache__/__init__.cpython-312.pyc |    Bin [31m5427[m -> [32m0[m bytes
 .../transport/__pycache__/aiohttp.cpython-312.pyc  |    Bin [31m9261[m -> [32m0[m bytes
 .../transport/__pycache__/sessions.cpython-312.pyc |    Bin [31m11736[m -> [32m0[m bytes
 .../google/auth/aio/transport/aiohttp.py           |    190 [31m-[m
 .../google/auth/aio/transport/sessions.py          |    268 [31m-[m
 .../venv/Lib/site-packages/google/auth/api_key.py  |     76 [31m-[m
 .../Lib/site-packages/google/auth/app_engine.py    |    180 [31m-[m
 backend/venv/Lib/site-packages/google/auth/aws.py  |    861 [31m-[m
 .../google/auth/compute_engine/__init__.py         |     22 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m494[m -> [32m0[m bytes
 .../__pycache__/_metadata.cpython-312.pyc          |    Bin [31m16466[m -> [32m0[m bytes
 .../__pycache__/_mtls.cpython-312.pyc              |    Bin [31m6924[m -> [32m0[m bytes
 .../__pycache__/credentials.cpython-312.pyc        |    Bin [31m21890[m -> [32m0[m bytes
 .../google/auth/compute_engine/_metadata.py        |    477 [31m-[m
 .../google/auth/compute_engine/_mtls.py            |    164 [31m-[m
 .../google/auth/compute_engine/credentials.py      |    558 [31m-[m
 .../Lib/site-packages/google/auth/credentials.py   |    665 [31m-[m
 .../site-packages/google/auth/crypt/__init__.py    |    105 [31m-[m
 .../crypt/__pycache__/__init__.cpython-312.pyc     |    Bin [31m3007[m -> [32m0[m bytes
 .../__pycache__/_cryptography_rsa.cpython-312.pyc  |    Bin [31m6933[m -> [32m0[m bytes
 .../crypt/__pycache__/_helpers.cpython-312.pyc     |    Bin [31m179[m -> [32m0[m bytes
 .../crypt/__pycache__/_python_rsa.cpython-312.pyc  |    Bin [31m8062[m -> [32m0[m bytes
 .../auth/crypt/__pycache__/base.cpython-312.pyc    |    Bin [31m4973[m -> [32m0[m bytes
 .../auth/crypt/__pycache__/es.cpython-312.pyc      |    Bin [31m10940[m -> [32m0[m bytes
 .../auth/crypt/__pycache__/es256.cpython-312.pyc   |    Bin [31m1326[m -> [32m0[m bytes
 .../auth/crypt/__pycache__/rsa.cpython-312.pyc     |    Bin [31m566[m -> [32m0[m bytes
 .../google/auth/crypt/_cryptography_rsa.py         |    151 [31m-[m
 .../site-packages/google/auth/crypt/_helpers.py    |      0
 .../site-packages/google/auth/crypt/_python_rsa.py |    175 [31m-[m
 .../Lib/site-packages/google/auth/crypt/base.py    |    127 [31m-[m
 .../venv/Lib/site-packages/google/auth/crypt/es.py |    221 [31m-[m
 .../Lib/site-packages/google/auth/crypt/es256.py   |     45 [31m-[m
 .../Lib/site-packages/google/auth/crypt/rsa.py     |     30 [31m-[m
 .../Lib/site-packages/google/auth/downscoped.py    |    512 [31m-[m
 .../site-packages/google/auth/environment_vars.py  |    103 [31m-[m
 .../Lib/site-packages/google/auth/exceptions.py    |    108 [31m-[m
 .../site-packages/google/auth/external_account.py  |    715 [31m-[m
 .../auth/external_account_authorized_user.py       |    457 [31m-[m
 backend/venv/Lib/site-packages/google/auth/iam.py  |    136 [31m-[m
 .../Lib/site-packages/google/auth/identity_pool.py |    574 [31m-[m
 .../google/auth/impersonated_credentials.py        |    705 [31m-[m
 backend/venv/Lib/site-packages/google/auth/jwt.py  |    879 [31m-[m
 .../venv/Lib/site-packages/google/auth/metrics.py  |    154 [31m-[m
 .../Lib/site-packages/google/auth/pluggable.py     |    454 [31m-[m
 .../venv/Lib/site-packages/google/auth/py.typed    |      2 [31m-[m
 .../google/auth/transport/__init__.py              |    104 [31m-[m
 .../transport/__pycache__/__init__.cpython-312.pyc |    Bin [31m3840[m -> [32m0[m bytes
 .../__pycache__/_aiohttp_requests.cpython-312.pyc  |    Bin [31m16550[m -> [32m0[m bytes
 .../__pycache__/_custom_tls_signer.cpython-312.pyc |    Bin [31m10572[m -> [32m0[m bytes
 .../__pycache__/_http_client.cpython-312.pyc       |    Bin [31m4792[m -> [32m0[m bytes
 .../__pycache__/_mtls_helper.cpython-312.pyc       |    Bin [31m18824[m -> [32m0[m bytes
 .../__pycache__/_requests_base.cpython-312.pyc     |    Bin [31m1691[m -> [32m0[m bytes
 .../transport/__pycache__/grpc.cpython-312.pyc     |    Bin [31m13867[m -> [32m0[m bytes
 .../transport/__pycache__/mtls.cpython-312.pyc     |    Bin [31m5106[m -> [32m0[m bytes
 .../transport/__pycache__/requests.cpython-312.pyc |    Bin [31m25864[m -> [32m0[m bytes
 .../transport/__pycache__/urllib3.cpython-312.pyc  |    Bin [31m19004[m -> [32m0[m bytes
 .../google/auth/transport/_aiohttp_requests.py     |    398 [31m-[m
 .../google/auth/transport/_custom_tls_signer.py    |    283 [31m-[m
 .../google/auth/transport/_http_client.py          |    115 [31m-[m
 .../google/auth/transport/_mtls_helper.py          |    503 [31m-[m
 .../google/auth/transport/_requests_base.py        |     53 [31m-[m
 .../site-packages/google/auth/transport/grpc.py    |    337 [31m-[m
 .../site-packages/google/auth/transport/mtls.py    |    129 [31m-[m
 .../google/auth/transport/requests.py              |    628 [31m-[m
 .../site-packages/google/auth/transport/urllib3.py |    489 [31m-[m
 .../venv/Lib/site-packages/google/auth/version.py  |     15 [31m-[m
 .../common_resources_pb2.cpython-312.pyc           |    Bin [31m2068[m -> [32m0[m bytes
 .../extended_operations_pb2.cpython-312.pyc        |    Bin [31m2164[m -> [32m0[m bytes
 .../google/cloud/common_resources.proto            |     52 [31m-[m
 .../google/cloud/common_resources_pb2.py           |     47 [31m-[m
 .../google/cloud/common_resources_pb2.pyi          |     20 [31m-[m
 .../google/cloud/extended_operations.proto         |    150 [31m-[m
 .../google/cloud/extended_operations_pb2.py        |     49 [31m-[m
 .../google/cloud/extended_operations_pb2.pyi       |     45 [31m-[m
 .../__pycache__/locations_pb2.cpython-312.pyc      |    Bin [31m3935[m -> [32m0[m bytes
 .../google/cloud/location/locations.proto          |    108 [31m-[m
 .../google/cloud/location/locations_pb2.py         |     75 [31m-[m
 .../google/cloud/location/locations_pb2.pyi        |     95 [31m-[m
 .../__pycache__/gapic_metadata_pb2.cpython-312.pyc |    Bin [31m3399[m -> [32m0[m bytes
 .../google/gapic/metadata/gapic_metadata.proto     |     98 [31m-[m
 .../google/gapic/metadata/gapic_metadata_pb2.py    |     67 [31m-[m
 .../google/gapic/metadata/gapic_metadata_pb2.pyi   |    122 [31m-[m
 .../site-packages/google/generativeai/__init__.py  |    105 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m2567[m -> [32m0[m bytes
 .../__pycache__/answer.cpython-312.pyc             |    Bin [31m14181[m -> [32m0[m bytes
 .../__pycache__/caching.cpython-312.pyc            |    Bin [31m12677[m -> [32m0[m bytes
 .../__pycache__/client.cpython-312.pyc             |    Bin [31m17150[m -> [32m0[m bytes
 .../__pycache__/embedding.cpython-312.pyc          |    Bin [31m12097[m -> [32m0[m bytes
 .../generativeai/__pycache__/files.cpython-312.pyc |    Bin [31m4524[m -> [32m0[m bytes
 .../__pycache__/generative_models.cpython-312.pyc  |    Bin [31m34786[m -> [32m0[m bytes
 .../__pycache__/models.cpython-312.pyc             |    Bin [31m16923[m -> [32m0[m bytes
 .../__pycache__/operations.cpython-312.pyc         |    Bin [31m6146[m -> [32m0[m bytes
 .../__pycache__/permission.cpython-312.pyc         |    Bin [31m6386[m -> [32m0[m bytes
 .../__pycache__/protos.cpython-312.pyc             |    Bin [31m2313[m -> [32m0[m bytes
 .../__pycache__/responder.cpython-312.pyc          |    Bin [31m25509[m -> [32m0[m bytes
 .../__pycache__/retriever.cpython-312.pyc          |    Bin [31m9435[m -> [32m0[m bytes
 .../__pycache__/string_utils.cpython-312.pyc       |    Bin [31m3347[m -> [32m0[m bytes
 .../generativeai/__pycache__/utils.cpython-312.pyc |    Bin [31m823[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m260[m -> [32m0[m bytes
 .../site-packages/google/generativeai/answer.py    |    363 [31m-[m
 .../site-packages/google/generativeai/caching.py   |    314 [31m-[m
 .../site-packages/google/generativeai/client.py    |    388 [31m-[m
 .../site-packages/google/generativeai/embedding.py |    312 [31m-[m
 .../Lib/site-packages/google/generativeai/files.py |    116 [31m-[m
 .../google/generativeai/generative_models.py       |    875 [31m-[m
 .../site-packages/google/generativeai/models.py    |    467 [31m-[m
 .../google/generativeai/notebook/__init__.py       |     32 [31m-[m
 .../notebook/__pycache__/__init__.cpython-312.pyc  |    Bin [31m829[m -> [32m0[m bytes
 .../__pycache__/argument_parser.cpython-312.pyc    |    Bin [31m5083[m -> [32m0[m bytes
 .../__pycache__/cmd_line_parser.cpython-312.pyc    |    Bin [31m21477[m -> [32m0[m bytes
 .../notebook/__pycache__/command.cpython-312.pyc   |    Bin [31m1635[m -> [32m0[m bytes
 .../__pycache__/command_utils.cpython-312.pyc      |    Bin [31m6986[m -> [32m0[m bytes
 .../__pycache__/compare_cmd.cpython-312.pyc        |    Bin [31m2500[m -> [32m0[m bytes
 .../__pycache__/compile_cmd.cpython-312.pyc        |    Bin [31m2546[m -> [32m0[m bytes
 .../notebook/__pycache__/eval_cmd.cpython-312.pyc  |    Bin [31m2685[m -> [32m0[m bytes
 .../notebook/__pycache__/flag_def.cpython-312.pyc  |    Bin [31m20013[m -> [32m0[m bytes
 .../__pycache__/gspread_client.cpython-312.pyc     |    Bin [31m9674[m -> [32m0[m bytes
 .../__pycache__/html_utils.cpython-312.pyc         |    Bin [31m1190[m -> [32m0[m bytes
 .../__pycache__/input_utils.cpython-312.pyc        |    Bin [31m3277[m -> [32m0[m bytes
 .../__pycache__/ipython_env.cpython-312.pyc        |    Bin [31m1771[m -> [32m0[m bytes
 .../__pycache__/ipython_env_impl.cpython-312.pyc   |    Bin [31m1201[m -> [32m0[m bytes
 .../notebook/__pycache__/magics.cpython-312.pyc    |    Bin [31m5234[m -> [32m0[m bytes
 .../__pycache__/magics_engine.cpython-312.pyc      |    Bin [31m5212[m -> [32m0[m bytes
 .../__pycache__/model_registry.cpython-312.pyc     |    Bin [31m2121[m -> [32m0[m bytes
 .../__pycache__/output_utils.cpython-312.pyc       |    Bin [31m2458[m -> [32m0[m bytes
 .../__pycache__/parsed_args_lib.cpython-312.pyc    |    Bin [31m2830[m -> [32m0[m bytes
 .../__pycache__/post_process_utils.cpython-312.pyc |    Bin [31m7677[m -> [32m0[m bytes
 .../post_process_utils_test_helper.cpython-312.pyc |    Bin [31m1023[m -> [32m0[m bytes
 .../notebook/__pycache__/py_utils.cpython-312.pyc  |    Bin [31m2434[m -> [32m0[m bytes
 .../notebook/__pycache__/run_cmd.cpython-312.pyc   |    Bin [31m2673[m -> [32m0[m bytes
 .../notebook/__pycache__/sheets_id.cpython-312.pyc |    Bin [31m4475[m -> [32m0[m bytes
 .../sheets_sanitize_url.cpython-312.pyc            |    Bin [31m3473[m -> [32m0[m bytes
 .../__pycache__/sheets_utils.cpython-312.pyc       |    Bin [31m5160[m -> [32m0[m bytes
 .../__pycache__/text_model.cpython-312.pyc         |    Bin [31m3065[m -> [32m0[m bytes
 .../generativeai/notebook/argument_parser.py       |    112 [31m-[m
 .../generativeai/notebook/cmd_line_parser.py       |    557 [31m-[m
 .../google/generativeai/notebook/command.py        |     45 [31m-[m
 .../google/generativeai/notebook/command_utils.py  |    164 [31m-[m
 .../google/generativeai/notebook/compare_cmd.py    |     71 [31m-[m
 .../google/generativeai/notebook/compile_cmd.py    |     66 [31m-[m
 .../google/generativeai/notebook/eval_cmd.py       |     75 [31m-[m
 .../google/generativeai/notebook/flag_def.py       |    503 [31m-[m
 .../google/generativeai/notebook/gspread_client.py |    232 [31m-[m
 .../google/generativeai/notebook/html_utils.py     |     46 [31m-[m
 .../google/generativeai/notebook/input_utils.py    |     73 [31m-[m
 .../google/generativeai/notebook/ipython_env.py    |     49 [31m-[m
 .../generativeai/notebook/ipython_env_impl.py      |     30 [31m-[m
 .../google/generativeai/notebook/lib/__init__.py   |     14 [31m-[m
 .../lib/__pycache__/__init__.cpython-312.pyc       |    Bin [31m194[m -> [32m0[m bytes
 .../lib/__pycache__/llm_function.cpython-312.pyc   |    Bin [31m18691[m -> [32m0[m bytes
 .../__pycache__/llmfn_input_utils.cpython-312.pyc  |    Bin [31m2802[m -> [32m0[m bytes
 .../llmfn_inputs_source.cpython-312.pyc            |    Bin [31m2678[m -> [32m0[m bytes
 .../__pycache__/llmfn_output_row.cpython-312.pyc   |    Bin [31m7822[m -> [32m0[m bytes
 .../lib/__pycache__/llmfn_outputs.cpython-312.pyc  |    Bin [31m9582[m -> [32m0[m bytes
 .../__pycache__/llmfn_post_process.cpython-312.pyc |    Bin [31m1348[m -> [32m0[m bytes
 .../llmfn_post_process_cmds.cpython-312.pyc        |    Bin [31m10400[m -> [32m0[m bytes
 .../notebook/lib/__pycache__/model.cpython-312.pyc |    Bin [31m2572[m -> [32m0[m bytes
 .../lib/__pycache__/prompt_utils.cpython-312.pyc   |    Bin [31m1090[m -> [32m0[m bytes
 .../lib/__pycache__/unique_fn.cpython-312.pyc      |    Bin [31m1329[m -> [32m0[m bytes
 .../generativeai/notebook/lib/llm_function.py      |    468 [31m-[m
 .../generativeai/notebook/lib/llmfn_input_utils.py |     81 [31m-[m
 .../notebook/lib/llmfn_inputs_source.py            |     69 [31m-[m
 .../generativeai/notebook/lib/llmfn_output_row.py  |    177 [31m-[m
 .../generativeai/notebook/lib/llmfn_outputs.py     |    250 [31m-[m
 .../notebook/lib/llmfn_post_process.py             |     74 [31m-[m
 .../notebook/lib/llmfn_post_process_cmds.py        |    246 [31m-[m
 .../google/generativeai/notebook/lib/model.py      |     69 [31m-[m
 .../generativeai/notebook/lib/prompt_utils.py      |     38 [31m-[m
 .../google/generativeai/notebook/lib/unique_fn.py  |     47 [31m-[m
 .../google/generativeai/notebook/magics.py         |    150 [31m-[m
 .../google/generativeai/notebook/magics_engine.py  |    124 [31m-[m
 .../google/generativeai/notebook/model_registry.py |     55 [31m-[m
 .../google/generativeai/notebook/output_utils.py   |     61 [31m-[m
 .../generativeai/notebook/parsed_args_lib.py       |     85 [31m-[m
 .../generativeai/notebook/post_process_utils.py    |    163 [31m-[m
 .../notebook/post_process_utils_test_helper.py     |     32 [31m-[m
 .../google/generativeai/notebook/py_utils.py       |     64 [31m-[m
 .../google/generativeai/notebook/run_cmd.py        |     75 [31m-[m
 .../google/generativeai/notebook/sheets_id.py      |    101 [31m-[m
 .../generativeai/notebook/sheets_sanitize_url.py   |     89 [31m-[m
 .../google/generativeai/notebook/sheets_utils.py   |    111 [31m-[m
 .../google/generativeai/notebook/text_model.py     |     72 [31m-[m
 .../google/generativeai/operations.py              |    158 [31m-[m
 .../google/generativeai/permission.py              |    167 [31m-[m
 .../site-packages/google/generativeai/protos.py    |     75 [31m-[m
 .../Lib/site-packages/google/generativeai/py.typed |      1 [31m-[m
 .../site-packages/google/generativeai/responder.py |    625 [31m-[m
 .../site-packages/google/generativeai/retriever.py |    255 [31m-[m
 .../google/generativeai/string_utils.py            |     84 [31m-[m
 .../google/generativeai/types/__init__.py          |     29 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m768[m -> [32m0[m bytes
 .../types/__pycache__/answer_types.cpython-312.pyc |    Bin [31m2349[m -> [32m0[m bytes
 .../__pycache__/caching_types.cpython-312.pyc      |    Bin [31m2466[m -> [32m0[m bytes
 .../__pycache__/citation_types.cpython-312.pyc     |    Bin [31m1320[m -> [32m0[m bytes
 .../__pycache__/content_types.cpython-312.pyc      |    Bin [31m39014[m -> [32m0[m bytes
 .../types/__pycache__/file_types.cpython-312.pyc   |    Bin [31m6501[m -> [32m0[m bytes
 .../__pycache__/generation_types.cpython-312.pyc   |    Bin [31m31391[m -> [32m0[m bytes
 .../types/__pycache__/helper_types.cpython-312.pyc |    Bin [31m3151[m -> [32m0[m bytes
 .../types/__pycache__/model_types.cpython-312.pyc  |    Bin [31m16667[m -> [32m0[m bytes
 .../__pycache__/palm_safety_types.cpython-312.pyc  |    Bin [31m13193[m -> [32m0[m bytes
 .../__pycache__/permission_types.cpython-312.pyc   |    Bin [31m19200[m -> [32m0[m bytes
 .../__pycache__/retriever_types.cpython-312.pyc    |    Bin [31m63855[m -> [32m0[m bytes
 .../types/__pycache__/safety_types.cpython-312.pyc |    Bin [31m13366[m -> [32m0[m bytes
 .../types/__pycache__/text_types.cpython-312.pyc   |    Bin [31m969[m -> [32m0[m bytes
 .../google/generativeai/types/answer_types.py      |     58 [31m-[m
 .../google/generativeai/types/caching_types.py     |     83 [31m-[m
 .../google/generativeai/types/citation_types.py    |     42 [31m-[m
 .../google/generativeai/types/content_types.py     |    999 [31m-[m
 .../google/generativeai/types/file_types.py        |    143 [31m-[m
 .../google/generativeai/types/generation_types.py  |    759 [31m-[m
 .../google/generativeai/types/helper_types.py      |     87 [31m-[m
 .../google/generativeai/types/model_types.py       |    393 [31m-[m
 .../google/generativeai/types/palm_safety_types.py |    286 [31m-[m
 .../google/generativeai/types/permission_types.py  |    479 [31m-[m
 .../google/generativeai/types/retriever_types.py   |   1698 [31m-[m
 .../google/generativeai/types/safety_types.py      |    303 [31m-[m
 .../google/generativeai/types/text_types.py        |     32 [31m-[m
 .../Lib/site-packages/google/generativeai/utils.py |     29 [31m-[m
 .../site-packages/google/generativeai/version.py   |     17 [31m-[m
 .../__pycache__/http_request_pb2.cpython-312.pyc   |    Bin [31m2204[m -> [32m0[m bytes
 .../__pycache__/log_severity_pb2.cpython-312.pyc   |    Bin [31m1873[m -> [32m0[m bytes
 .../google/logging/type/http_request.proto         |     95 [31m-[m
 .../google/logging/type/http_request_pb2.py        |     49 [31m-[m
 .../google/logging/type/http_request_pb2.pyi       |     91 [31m-[m
 .../google/logging/type/log_severity.proto         |     71 [31m-[m
 .../google/logging/type/log_severity_pb2.py        |     47 [31m-[m
 .../google/logging/type/log_severity_pb2.pyi       |     42 [31m-[m
 .../__pycache__/operations_grpc.cpython-312.pyc    |    Bin [31m300[m -> [32m0[m bytes
 .../operations_grpc_pb2.cpython-312.pyc            |    Bin [31m566[m -> [32m0[m bytes
 .../__pycache__/operations_pb2.cpython-312.pyc     |    Bin [31m954[m -> [32m0[m bytes
 .../operations_pb2_grpc.cpython-312.pyc            |    Bin [31m12041[m -> [32m0[m bytes
 .../__pycache__/operations_proto.cpython-312.pyc   |    Bin [31m302[m -> [32m0[m bytes
 .../operations_proto_pb2.cpython-312.pyc           |    Bin [31m5581[m -> [32m0[m bytes
 .../google/longrunning/operations_grpc.py          |     20 [31m-[m
 .../google/longrunning/operations_grpc_pb2.py      |     16 [31m-[m
 .../google/longrunning/operations_pb2.py           |     45 [31m-[m
 .../google/longrunning/operations_pb2_grpc.py      |    339 [31m-[m
 .../google/longrunning/operations_proto.proto      |    246 [31m-[m
 .../google/longrunning/operations_proto.py         |      6 [31m-[m
 .../google/longrunning/operations_proto_pb2.py     |     97 [31m-[m
 .../google/longrunning/operations_proto_pb2.pyi    |    125 [31m-[m
 .../Lib/site-packages/google/oauth2/__init__.py    |     36 [31m-[m
 .../oauth2/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1003[m -> [32m0[m bytes
 .../oauth2/__pycache__/_client.cpython-312.pyc     |    Bin [31m21565[m -> [32m0[m bytes
 .../__pycache__/_client_async.cpython-312.pyc      |    Bin [31m10336[m -> [32m0[m bytes
 .../__pycache__/_credentials_async.cpython-312.pyc |    Bin [31m4798[m -> [32m0[m bytes
 .../__pycache__/_id_token_async.cpython-312.pyc    |    Bin [31m10586[m -> [32m0[m bytes
 .../__pycache__/_reauth_async.cpython-312.pyc      |    Bin [31m11876[m -> [32m0[m bytes
 .../_service_account_async.cpython-312.pyc         |    Bin [31m5490[m -> [32m0[m bytes
 .../oauth2/__pycache__/challenges.cpython-312.pyc  |    Bin [31m12339[m -> [32m0[m bytes
 .../oauth2/__pycache__/credentials.cpython-312.pyc |    Bin [31m27196[m -> [32m0[m bytes
 .../__pycache__/gdch_credentials.cpython-312.pyc   |    Bin [31m9586[m -> [32m0[m bytes
 .../oauth2/__pycache__/id_token.cpython-312.pyc    |    Bin [31m13240[m -> [32m0[m bytes
 .../oauth2/__pycache__/reauth.cpython-312.pyc      |    Bin [31m12458[m -> [32m0[m bytes
 .../__pycache__/service_account.cpython-312.pyc    |    Bin [31m36708[m -> [32m0[m bytes
 .../google/oauth2/__pycache__/sts.cpython-312.pyc  |    Bin [31m7317[m -> [32m0[m bytes
 .../oauth2/__pycache__/utils.cpython-312.pyc       |    Bin [31m6949[m -> [32m0[m bytes
 .../__pycache__/webauthn_handler.cpython-312.pyc   |    Bin [31m4327[m -> [32m0[m bytes
 .../webauthn_handler_factory.cpython-312.pyc       |    Bin [31m1088[m -> [32m0[m bytes
 .../__pycache__/webauthn_types.cpython-312.pyc     |    Bin [31m7445[m -> [32m0[m bytes
 .../Lib/site-packages/google/oauth2/_client.py     |    625 [31m-[m
 .../site-packages/google/oauth2/_client_async.py   |    286 [31m-[m
 .../google/oauth2/_credentials_async.py            |    118 [31m-[m
 .../site-packages/google/oauth2/_id_token_async.py |    285 [31m-[m
 .../site-packages/google/oauth2/_reauth_async.py   |    328 [31m-[m
 .../google/oauth2/_service_account_async.py        |    132 [31m-[m
 .../Lib/site-packages/google/oauth2/challenges.py  |    281 [31m-[m
 .../Lib/site-packages/google/oauth2/credentials.py |    614 [31m-[m
 .../google/oauth2/gdch_credentials.py              |    251 [31m-[m
 .../Lib/site-packages/google/oauth2/id_token.py    |    370 [31m-[m
 .../venv/Lib/site-packages/google/oauth2/py.typed  |      2 [31m-[m
 .../venv/Lib/site-packages/google/oauth2/reauth.py |    369 [31m-[m
 .../site-packages/google/oauth2/service_account.py |    881 [31m-[m
 .../venv/Lib/site-packages/google/oauth2/sts.py    |    201 [31m-[m
 .../venv/Lib/site-packages/google/oauth2/utils.py  |    168 [31m-[m
 .../google/oauth2/webauthn_handler.py              |     82 [31m-[m
 .../google/oauth2/webauthn_handler_factory.py      |     16 [31m-[m
 .../site-packages/google/oauth2/webauthn_types.py  |    156 [31m-[m
 .../Lib/site-packages/google/protobuf/__init__.py  |     10 [31m-[m
 .../protobuf/__pycache__/__init__.cpython-312.pyc  |    Bin [31m206[m -> [32m0[m bytes
 .../protobuf/__pycache__/any.cpython-312.pyc       |    Bin [31m1464[m -> [32m0[m bytes
 .../protobuf/__pycache__/any_pb2.cpython-312.pyc   |    Bin [31m1846[m -> [32m0[m bytes
 .../protobuf/__pycache__/api_pb2.cpython-312.pyc   |    Bin [31m2865[m -> [32m0[m bytes
 .../__pycache__/descriptor.cpython-312.pyc         |    Bin [31m57736[m -> [32m0[m bytes
 .../descriptor_database.cpython-312.pyc            |    Bin [31m6714[m -> [32m0[m bytes
 .../__pycache__/descriptor_pb2.cpython-312.pyc     |    Bin [31m322912[m -> [32m0[m bytes
 .../__pycache__/descriptor_pool.cpython-312.pyc    |    Bin [31m56338[m -> [32m0[m bytes
 .../protobuf/__pycache__/duration.cpython-312.pyc  |    Bin [31m3917[m -> [32m0[m bytes
 .../__pycache__/duration_pb2.cpython-312.pyc       |    Bin [31m1903[m -> [32m0[m bytes
 .../protobuf/__pycache__/empty_pb2.cpython-312.pyc |    Bin [31m1824[m -> [32m0[m bytes
 .../__pycache__/field_mask_pb2.cpython-312.pyc     |    Bin [31m1891[m -> [32m0[m bytes
 .../__pycache__/json_format.cpython-312.pyc        |    Bin [31m43066[m -> [32m0[m bytes
 .../protobuf/__pycache__/message.cpython-312.pyc   |    Bin [31m15232[m -> [32m0[m bytes
 .../__pycache__/message_factory.cpython-312.pyc    |    Bin [31m8698[m -> [32m0[m bytes
 .../protobuf/__pycache__/proto.cpython-312.pyc     |    Bin [31m4119[m -> [32m0[m bytes
 .../__pycache__/proto_builder.cpython-312.pyc      |    Bin [31m4455[m -> [32m0[m bytes
 .../__pycache__/proto_json.cpython-312.pyc         |    Bin [31m3080[m -> [32m0[m bytes
 .../__pycache__/reflection.cpython-312.pyc         |    Bin [31m2663[m -> [32m0[m bytes
 .../__pycache__/runtime_version.cpython-312.pyc    |    Bin [31m4213[m -> [32m0[m bytes
 .../protobuf/__pycache__/service.cpython-312.pyc   |    Bin [31m9375[m -> [32m0[m bytes
 .../__pycache__/service_reflection.cpython-312.pyc |    Bin [31m12424[m -> [32m0[m bytes
 .../__pycache__/source_context_pb2.cpython-312.pyc |    Bin [31m1934[m -> [32m0[m bytes
 .../__pycache__/struct_pb2.cpython-312.pyc         |    Bin [31m2807[m -> [32m0[m bytes
 .../__pycache__/symbol_database.cpython-312.pyc    |    Bin [31m8636[m -> [32m0[m bytes
 .../__pycache__/text_encoding.cpython-312.pyc      |    Bin [31m4179[m -> [32m0[m bytes
 .../__pycache__/text_format.cpython-312.pyc        |    Bin [31m75264[m -> [32m0[m bytes
 .../protobuf/__pycache__/timestamp.cpython-312.pyc |    Bin [31m4565[m -> [32m0[m bytes
 .../__pycache__/timestamp_pb2.cpython-312.pyc      |    Bin [31m1913[m -> [32m0[m bytes
 .../protobuf/__pycache__/type_pb2.cpython-312.pyc  |    Bin [31m4290[m -> [32m0[m bytes
 .../__pycache__/unknown_fields.cpython-312.pyc     |    Bin [31m4333[m -> [32m0[m bytes
 .../__pycache__/wrappers_pb2.cpython-312.pyc       |    Bin [31m2887[m -> [32m0[m bytes
 .../venv/Lib/site-packages/google/protobuf/any.py  |     39 [31m-[m
 .../Lib/site-packages/google/protobuf/any_pb2.py   |     37 [31m-[m
 .../Lib/site-packages/google/protobuf/api_pb2.py   |     43 [31m-[m
 .../google/protobuf/compiler/__init__.py           |      0
 .../compiler/__pycache__/__init__.cpython-312.pyc  |    Bin [31m186[m -> [32m0[m bytes
 .../__pycache__/plugin_pb2.cpython-312.pyc         |    Bin [31m3326[m -> [32m0[m bytes
 .../google/protobuf/compiler/plugin_pb2.py         |     46 [31m-[m
 .../site-packages/google/protobuf/descriptor.py    |   1511 [31m-[m
 .../google/protobuf/descriptor_database.py         |    154 [31m-[m
 .../google/protobuf/descriptor_pb2.py              |   3169 [31m-[m
 .../google/protobuf/descriptor_pool.py             |   1355 [31m-[m
 .../Lib/site-packages/google/protobuf/duration.py  |    100 [31m-[m
 .../site-packages/google/protobuf/duration_pb2.py  |     37 [31m-[m
 .../Lib/site-packages/google/protobuf/empty_pb2.py |     37 [31m-[m
 .../google/protobuf/field_mask_pb2.py              |     37 [31m-[m
 .../google/protobuf/internal/__init__.py           |      7 [31m-[m
 .../internal/__pycache__/__init__.cpython-312.pyc  |    Bin [31m186[m -> [32m0[m bytes
 .../__pycache__/_parameterized.cpython-312.pyc     |    Bin [31m17332[m -> [32m0[m bytes
 .../__pycache__/api_implementation.cpython-312.pyc |    Bin [31m3307[m -> [32m0[m bytes
 .../internal/__pycache__/builder.cpython-312.pyc   |    Bin [31m5201[m -> [32m0[m bytes
 .../__pycache__/containers.cpython-312.pyc         |    Bin [31m32309[m -> [32m0[m bytes
 .../internal/__pycache__/decoder.cpython-312.pyc   |    Bin [31m38522[m -> [32m0[m bytes
 .../internal/__pycache__/encoder.cpython-312.pyc   |    Bin [31m32503[m -> [32m0[m bytes
 .../__pycache__/enum_type_wrapper.cpython-312.pyc  |    Bin [31m4840[m -> [32m0[m bytes
 .../__pycache__/extension_dict.cpython-312.pyc     |    Bin [31m8726[m -> [32m0[m bytes
 .../__pycache__/field_mask.cpython-312.pyc         |    Bin [31m13768[m -> [32m0[m bytes
 .../__pycache__/message_listener.cpython-312.pyc   |    Bin [31m2415[m -> [32m0[m bytes
 .../python_edition_defaults.cpython-312.pyc        |    Bin [31m505[m -> [32m0[m bytes
 .../__pycache__/python_message.cpython-312.pyc     |    Bin [31m65963[m -> [32m0[m bytes
 .../__pycache__/testing_refleaks.cpython-312.pyc   |    Bin [31m5206[m -> [32m0[m bytes
 .../__pycache__/type_checkers.cpython-312.pyc      |    Bin [31m19974[m -> [32m0[m bytes
 .../__pycache__/well_known_types.cpython-312.pyc   |    Bin [31m31584[m -> [32m0[m bytes
 .../__pycache__/wire_format.cpython-312.pyc        |    Bin [31m8284[m -> [32m0[m bytes
 .../google/protobuf/internal/_parameterized.py     |    420 [31m-[m
 .../google/protobuf/internal/api_implementation.py |    142 [31m-[m
 .../google/protobuf/internal/builder.py            |    117 [31m-[m
 .../google/protobuf/internal/containers.py         |    677 [31m-[m
 .../google/protobuf/internal/decoder.py            |   1121 [31m-[m
 .../google/protobuf/internal/encoder.py            |    806 [31m-[m
 .../google/protobuf/internal/enum_type_wrapper.py  |    112 [31m-[m
 .../google/protobuf/internal/extension_dict.py     |    194 [31m-[m
 .../google/protobuf/internal/field_mask.py         |    310 [31m-[m
 .../google/protobuf/internal/message_listener.py   |     55 [31m-[m
 .../protobuf/internal/python_edition_defaults.py   |      5 [31m-[m
 .../google/protobuf/internal/python_message.py     |   1586 [31m-[m
 .../google/protobuf/internal/testing_refleaks.py   |    119 [31m-[m
 .../google/protobuf/internal/type_checkers.py      |    408 [31m-[m
 .../google/protobuf/internal/well_known_types.py   |    678 [31m-[m
 .../google/protobuf/internal/wire_format.py        |    245 [31m-[m
 .../site-packages/google/protobuf/json_format.py   |   1069 [31m-[m
 .../Lib/site-packages/google/protobuf/message.py   |    422 [31m-[m
 .../google/protobuf/message_factory.py             |    237 [31m-[m
 .../Lib/site-packages/google/protobuf/proto.py     |    116 [31m-[m
 .../site-packages/google/protobuf/proto_builder.py |    111 [31m-[m
 .../site-packages/google/protobuf/proto_json.py    |     83 [31m-[m
 .../google/protobuf/pyext/__init__.py              |      0
 .../pyext/__pycache__/__init__.cpython-312.pyc     |    Bin [31m183[m -> [32m0[m bytes
 .../pyext/__pycache__/cpp_message.cpython-312.pyc  |    Bin [31m1665[m -> [32m0[m bytes
 .../google/protobuf/pyext/cpp_message.py           |     49 [31m-[m
 .../site-packages/google/protobuf/reflection.py    |     85 [31m-[m
 .../google/protobuf/runtime_version.py             |    124 [31m-[m
 .../Lib/site-packages/google/protobuf/service.py   |    213 [31m-[m
 .../google/protobuf/service_reflection.py          |    272 [31m-[m
 .../google/protobuf/source_context_pb2.py          |     37 [31m-[m
 .../site-packages/google/protobuf/struct_pb2.py    |     47 [31m-[m
 .../google/protobuf/symbol_database.py             |    197 [31m-[m
 .../google/protobuf/testdata/__init__.py           |      0
 .../testdata/__pycache__/__init__.cpython-312.pyc  |    Bin [31m186[m -> [32m0[m bytes
 .../site-packages/google/protobuf/text_encoding.py |    106 [31m-[m
 .../site-packages/google/protobuf/text_format.py   |   1864 [31m-[m
 .../Lib/site-packages/google/protobuf/timestamp.py |    112 [31m-[m
 .../site-packages/google/protobuf/timestamp_pb2.py |     37 [31m-[m
 .../Lib/site-packages/google/protobuf/type_pb2.py  |     53 [31m-[m
 .../google/protobuf/unknown_fields.py              |     97 [31m-[m
 .../site-packages/google/protobuf/util/__init__.py |      0
 .../util/__pycache__/__init__.cpython-312.pyc      |    Bin [31m182[m -> [32m0[m bytes
 .../site-packages/google/protobuf/wrappers_pb2.py  |     53 [31m-[m
 .../rpc/__pycache__/code_pb2.cpython-312.pyc       |    Bin [31m1763[m -> [32m0[m bytes
 .../__pycache__/error_details_pb2.cpython-312.pyc  |    Bin [31m4534[m -> [32m0[m bytes
 .../rpc/__pycache__/http_pb2.cpython-312.pyc       |    Bin [31m1880[m -> [32m0[m bytes
 .../rpc/__pycache__/status_pb2.cpython-312.pyc     |    Bin [31m1648[m -> [32m0[m bytes
 .../venv/Lib/site-packages/google/rpc/code.proto   |    186 [31m-[m
 .../venv/Lib/site-packages/google/rpc/code_pb2.py  |     45 [31m-[m
 .../venv/Lib/site-packages/google/rpc/code_pb2.pyi |     58 [31m-[m
 .../attribute_context_pb2.cpython-312.pyc          |    Bin [31m5638[m -> [32m0[m bytes
 .../__pycache__/audit_context_pb2.cpython-312.pyc  |    Bin [31m1857[m -> [32m0[m bytes
 .../google/rpc/context/attribute_context.proto     |    345 [31m-[m
 .../google/rpc/context/attribute_context_pb2.py    |     86 [31m-[m
 .../google/rpc/context/attribute_context_pb2.pyi   |    309 [31m-[m
 .../google/rpc/context/audit_context.proto         |     48 [31m-[m
 .../google/rpc/context/audit_context_pb2.py        |     49 [31m-[m
 .../google/rpc/context/audit_context_pb2.pyi       |     51 [31m-[m
 .../site-packages/google/rpc/error_details.proto   |    363 [31m-[m
 .../site-packages/google/rpc/error_details_pb2.py  |     85 [31m-[m
 .../site-packages/google/rpc/error_details_pb2.pyi |    246 [31m-[m
 .../venv/Lib/site-packages/google/rpc/http.proto   |     64 [31m-[m
 .../venv/Lib/site-packages/google/rpc/http_pb2.py  |     49 [31m-[m
 .../venv/Lib/site-packages/google/rpc/http_pb2.pyi |     71 [31m-[m
 .../venv/Lib/site-packages/google/rpc/status.proto |     49 [31m-[m
 .../Lib/site-packages/google/rpc/status_pb2.py     |     47 [31m-[m
 .../Lib/site-packages/google/rpc/status_pb2.pyi    |     41 [31m-[m
 .../calendar_period_pb2.cpython-312.pyc            |    Bin [31m1696[m -> [32m0[m bytes
 .../type/__pycache__/color_pb2.cpython-312.pyc     |    Bin [31m1676[m -> [32m0[m bytes
 .../type/__pycache__/date_pb2.cpython-312.pyc      |    Bin [31m1513[m -> [32m0[m bytes
 .../type/__pycache__/datetime_pb2.cpython-312.pyc  |    Bin [31m1971[m -> [32m0[m bytes
 .../type/__pycache__/dayofweek_pb2.cpython-312.pyc |    Bin [31m1647[m -> [32m0[m bytes
 .../type/__pycache__/decimal_pb2.cpython-312.pyc   |    Bin [31m1519[m -> [32m0[m bytes
 .../type/__pycache__/expr_pb2.cpython-312.pyc      |    Bin [31m1539[m -> [32m0[m bytes
 .../type/__pycache__/fraction_pb2.cpython-312.pyc  |    Bin [31m1554[m -> [32m0[m bytes
 .../type/__pycache__/interval_pb2.cpython-312.pyc  |    Bin [31m1725[m -> [32m0[m bytes
 .../type/__pycache__/latlng_pb2.cpython-312.pyc    |    Bin [31m1530[m -> [32m0[m bytes
 .../__pycache__/localized_text_pb2.cpython-312.pyc |    Bin [31m1621[m -> [32m0[m bytes
 .../type/__pycache__/money_pb2.cpython-312.pyc     |    Bin [31m1535[m -> [32m0[m bytes
 .../type/__pycache__/month_pb2.cpython-312.pyc     |    Bin [31m1646[m -> [32m0[m bytes
 .../__pycache__/phone_number_pb2.cpython-312.pyc   |    Bin [31m1821[m -> [32m0[m bytes
 .../__pycache__/postal_address_pb2.cpython-312.pyc |    Bin [31m1819[m -> [32m0[m bytes
 .../__pycache__/quaternion_pb2.cpython-312.pyc     |    Bin [31m1586[m -> [32m0[m bytes
 .../type/__pycache__/timeofday_pb2.cpython-312.pyc |    Bin [31m1595[m -> [32m0[m bytes
 .../google/type/calendar_period.proto              |     56 [31m-[m
 .../google/type/calendar_period_pb2.py             |     47 [31m-[m
 .../google/type/calendar_period_pb2.pyi            |     40 [31m-[m
 .../venv/Lib/site-packages/google/type/color.proto |    174 [31m-[m
 .../Lib/site-packages/google/type/color_pb2.py     |     47 [31m-[m
 .../Lib/site-packages/google/type/color_pb2.pyi    |     42 [31m-[m
 .../venv/Lib/site-packages/google/type/date.proto  |     52 [31m-[m
 .../venv/Lib/site-packages/google/type/date_pb2.py |     45 [31m-[m
 .../Lib/site-packages/google/type/date_pb2.pyi     |     36 [31m-[m
 .../Lib/site-packages/google/type/datetime.proto   |    104 [31m-[m
 .../Lib/site-packages/google/type/datetime_pb2.py  |     51 [31m-[m
 .../Lib/site-packages/google/type/datetime_pb2.pyi |     77 [31m-[m
 .../Lib/site-packages/google/type/dayofweek.proto  |     50 [31m-[m
 .../Lib/site-packages/google/type/dayofweek_pb2.py |     47 [31m-[m
 .../site-packages/google/type/dayofweek_pb2.pyi    |     40 [31m-[m
 .../Lib/site-packages/google/type/decimal.proto    |     95 [31m-[m
 .../Lib/site-packages/google/type/decimal_pb2.py   |     45 [31m-[m
 .../Lib/site-packages/google/type/decimal_pb2.pyi  |     27 [31m-[m
 .../venv/Lib/site-packages/google/type/expr.proto  |     73 [31m-[m
 .../venv/Lib/site-packages/google/type/expr_pb2.py |     45 [31m-[m
 .../Lib/site-packages/google/type/expr_pb2.pyi     |     39 [31m-[m
 .../Lib/site-packages/google/type/fraction.proto   |     33 [31m-[m
 .../Lib/site-packages/google/type/fraction_pb2.py  |     47 [31m-[m
 .../Lib/site-packages/google/type/fraction_pb2.pyi |     31 [31m-[m
 .../Lib/site-packages/google/type/interval.proto   |     46 [31m-[m
 .../Lib/site-packages/google/type/interval_pb2.py  |     49 [31m-[m
 .../Lib/site-packages/google/type/interval_pb2.pyi |     36 [31m-[m
 .../Lib/site-packages/google/type/latlng.proto     |     37 [31m-[m
 .../Lib/site-packages/google/type/latlng_pb2.py    |     45 [31m-[m
 .../Lib/site-packages/google/type/latlng_pb2.pyi   |     31 [31m-[m
 .../site-packages/google/type/localized_text.proto |     36 [31m-[m
 .../google/type/localized_text_pb2.py              |     47 [31m-[m
 .../google/type/localized_text_pb2.pyi             |     31 [31m-[m
 .../venv/Lib/site-packages/google/type/money.proto |     42 [31m-[m
 .../Lib/site-packages/google/type/money_pb2.py     |     45 [31m-[m
 .../Lib/site-packages/google/type/money_pb2.pyi    |     36 [31m-[m
 .../venv/Lib/site-packages/google/type/month.proto |     65 [31m-[m
 .../Lib/site-packages/google/type/month_pb2.py     |     45 [31m-[m
 .../Lib/site-packages/google/type/month_pb2.pyi    |     50 [31m-[m
 .../site-packages/google/type/phone_number.proto   |    113 [31m-[m
 .../site-packages/google/type/phone_number_pb2.py  |     49 [31m-[m
 .../site-packages/google/type/phone_number_pb2.pyi |     48 [31m-[m
 .../site-packages/google/type/postal_address.proto |    134 [31m-[m
 .../google/type/postal_address_pb2.py              |     47 [31m-[m
 .../google/type/postal_address_pb2.pyi             |     74 [31m-[m
 .../Lib/site-packages/google/type/quaternion.proto |     94 [31m-[m
 .../site-packages/google/type/quaternion_pb2.py    |     47 [31m-[m
 .../site-packages/google/type/quaternion_pb2.pyi   |     39 [31m-[m
 .../Lib/site-packages/google/type/timeofday.proto  |     44 [31m-[m
 .../Lib/site-packages/google/type/timeofday_pb2.py |     47 [31m-[m
 .../site-packages/google/type/timeofday_pb2.pyi    |     39 [31m-[m
 .../INSTALLER                                      |      1 [31m-[m
 .../LICENSE                                        |    202 [31m-[m
 .../METADATA                                       |    139 [31m-[m
 .../RECORD                                         |    689 [31m-[m
 .../WHEEL                                          |      5 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../google_api_core-2.28.1.dist-info/INSTALLER     |      1 [31m-[m
 .../google_api_core-2.28.1.dist-info/METADATA      |     79 [31m-[m
 .../google_api_core-2.28.1.dist-info/RECORD        |    133 [31m-[m
 .../google_api_core-2.28.1.dist-info/WHEEL         |      5 [31m-[m
 .../licenses/LICENSE                               |    202 [31m-[m
 .../google_api_core-2.28.1.dist-info/top_level.txt |      1 [31m-[m
 .../INSTALLER                                      |      1 [31m-[m
 .../METADATA                                       |    164 [31m-[m
 .../RECORD                                         |    608 [31m-[m
 .../WHEEL                                          |      5 [31m-[m
 .../licenses/LICENSE                               |    201 [31m-[m
 .../top_level.txt                                  |      3 [31m-[m
 .../google_auth-2.45.0.dist-info/INSTALLER         |      1 [31m-[m
 .../google_auth-2.45.0.dist-info/METADATA          |    185 [31m-[m
 .../google_auth-2.45.0.dist-info/RECORD            |    160 [31m-[m
 .../google_auth-2.45.0.dist-info/WHEEL             |      6 [31m-[m
 .../google_auth-2.45.0.dist-info/licenses/LICENSE  |    201 [31m-[m
 .../google_auth-2.45.0.dist-info/top_level.txt     |      1 [31m-[m
 .../google_auth_httplib2-0.3.0.dist-info/INSTALLER |      1 [31m-[m
 .../google_auth_httplib2-0.3.0.dist-info/METADATA  |     91 [31m-[m
 .../google_auth_httplib2-0.3.0.dist-info/RECORD    |      8 [31m-[m
 .../google_auth_httplib2-0.3.0.dist-info/WHEEL     |      5 [31m-[m
 .../licenses/LICENSE                               |    201 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../venv/Lib/site-packages/google_auth_httplib2.py |    304 [31m-[m
 .../google_generativeai-0.8.6-py3.13-nspkg.pth     |      1 [31m-[m
 .../google_generativeai-0.8.6.dist-info/INSTALLER  |      1 [31m-[m
 .../google_generativeai-0.8.6.dist-info/LICENSE    |    202 [31m-[m
 .../google_generativeai-0.8.6.dist-info/METADATA   |     81 [31m-[m
 .../google_generativeai-0.8.6.dist-info/RECORD     |    146 [31m-[m
 .../google_generativeai-0.8.6.dist-info/REQUESTED  |      0
 .../google_generativeai-0.8.6.dist-info/WHEEL      |      5 [31m-[m
 .../namespace_packages.txt                         |      1 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../Lib/site-packages/googleapiclient/__init__.py  |     27 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m767[m -> [32m0[m bytes
 .../__pycache__/_auth.cpython-312.pyc              |    Bin [31m5960[m -> [32m0[m bytes
 .../__pycache__/_helpers.cpython-312.pyc           |    Bin [31m7180[m -> [32m0[m bytes
 .../__pycache__/channel.cpython-312.pyc            |    Bin [31m11594[m -> [32m0[m bytes
 .../__pycache__/discovery.cpython-312.pyc          |    Bin [31m62916[m -> [32m0[m bytes
 .../__pycache__/errors.cpython-312.pyc             |    Bin [31m8017[m -> [32m0[m bytes
 .../__pycache__/http.cpython-312.pyc               |    Bin [31m72220[m -> [32m0[m bytes
 .../__pycache__/mimeparse.cpython-312.pyc          |    Bin [31m7809[m -> [32m0[m bytes
 .../__pycache__/model.cpython-312.pyc              |    Bin [31m16164[m -> [32m0[m bytes
 .../__pycache__/sample_tools.cpython-312.pyc       |    Bin [31m3929[m -> [32m0[m bytes
 .../__pycache__/schema.cpython-312.pyc             |    Bin [31m12617[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m206[m -> [32m0[m bytes
 .../Lib/site-packages/googleapiclient/_auth.py     |    167 [31m-[m
 .../Lib/site-packages/googleapiclient/_helpers.py  |    207 [31m-[m
 .../Lib/site-packages/googleapiclient/channel.py   |    315 [31m-[m
 .../Lib/site-packages/googleapiclient/discovery.py |   1662 [31m-[m
 .../googleapiclient/discovery_cache/__init__.py    |     78 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m2650[m -> [32m0[m bytes
 .../__pycache__/appengine_memcache.cpython-312.pyc |    Bin [31m1967[m -> [32m0[m bytes
 .../__pycache__/base.cpython-312.pyc               |    Bin [31m1403[m -> [32m0[m bytes
 .../__pycache__/file_cache.cpython-312.pyc         |    Bin [31m6473[m -> [32m0[m bytes
 .../discovery_cache/appengine_memcache.py          |     55 [31m-[m
 .../googleapiclient/discovery_cache/base.py        |     46 [31m-[m
 .../documents/abusiveexperiencereport.v1.json      |    225 [31m-[m
 .../documents/acceleratedmobilepageurl.v1.json     |    235 [31m-[m
 .../documents/accessapproval.v1.json               |   1415 [31m-[m
 .../documents/accesscontextmanager.v1.json         |   2738 [31m-[m
 .../documents/accesscontextmanager.v1beta.json     |   1084 [31m-[m
 .../discovery_cache/documents/acmedns.v1.json      |    222 [31m-[m
 .../documents/addressvalidation.v1.json            |    856 [31m-[m
 .../documents/adexchangebuyer.v1.2.json            |    596 [31m-[m
 .../documents/adexchangebuyer.v1.3.json            |   1686 [31m-[m
 .../documents/adexchangebuyer.v1.4.json            |   3752 [31m-[m
 .../documents/adexchangebuyer2.v2beta1.json        |   6694 [31m-[m
 .../documents/adexperiencereport.v1.json           |    268 [31m-[m
 .../documents/admin.datatransfer_v1.json           |    453 [31m-[m
 .../documents/admin.datatransferv1.json            |    453 [31m-[m
 .../documents/admin.directory_v1.json              |   8796 [31m--[m
 .../documents/admin.directoryv1.json               |   8796 [31m--[m
 .../documents/admin.reports_v1.json                |   1372 [31m-[m
 .../discovery_cache/documents/admin.reportsv1.json |   1372 [31m-[m
 .../discovery_cache/documents/admob.v1.json        |   1253 [31m-[m
 .../discovery_cache/documents/admob.v1beta.json    |   2389 [31m-[m
 .../discovery_cache/documents/adsense.v2.json      |   2960 [31m-[m
 .../documents/adsensehost.v4.1.json                |   1573 [31m-[m
 .../documents/adsenseplatform.v1.json              |    721 [31m-[m
 .../documents/adsenseplatform.v1alpha.json         |   1125 [31m-[m
 .../documents/advisorynotifications.v1.json        |    656 [31m-[m
 .../discovery_cache/documents/aiplatform.v1.json   |  58783 [31m---------[m
 .../documents/aiplatform.v1beta1.json              |  73217 [31m-----------[m
 .../discovery_cache/documents/airquality.v1.json   |    875 [31m-[m
 .../documents/alertcenter.v1beta1.json             |   2358 [31m-[m
 .../discovery_cache/documents/alloydb.v1.json      |   6613 [31m-[m
 .../discovery_cache/documents/alloydb.v1alpha.json |   6894 [31m-[m
 .../discovery_cache/documents/alloydb.v1beta.json  |   6870 [31m-[m
 .../discovery_cache/documents/analytics.v3.json    |   7459 [31m--[m
 .../documents/analyticsadmin.v1alpha.json          |   9405 [31m--[m
 .../documents/analyticsadmin.v1beta.json           |   3579 [31m-[m
 .../documents/analyticsdata.v1alpha.json           |   1547 [31m-[m
 .../documents/analyticsdata.v1beta.json            |   2306 [31m-[m
 .../discovery_cache/documents/analyticshub.v1.json |   2926 [31m-[m
 .../documents/analyticshub.v1beta1.json            |   1514 [31m-[m
 .../documents/analyticsreporting.v4.json           |   1683 [31m-[m
 .../documents/androiddeviceprovisioning.v1.json    |   1994 [31m-[m
 .../documents/androidenterprise.v1.json            |   5104 [31m-[m
 .../documents/androidmanagement.v1.json            |   8228 [31m--[m
 .../documents/androidpublisher.v3.json             |  12735 [31m--[m
 .../discovery_cache/documents/apigateway.v1.json   |   1824 [31m-[m
 .../documents/apigateway.v1beta.json               |   1852 [31m-[m
 .../discovery_cache/documents/apigee.v1.json       |  20594 [31m---[m
 .../documents/apigeeregistry.v1.json               |   4191 [31m-[m
 .../discovery_cache/documents/apihub.v1.json       |   6601 [31m-[m
 .../discovery_cache/documents/apikeys.v2.json      |    702 [31m-[m
 .../discovery_cache/documents/apim.v1alpha.json    |   1709 [31m-[m
 .../discovery_cache/documents/appengine.v1.json    |   5123 [31m-[m
 .../documents/appengine.v1alpha.json               |   2312 [31m-[m
 .../documents/appengine.v1beta.json                |   5442 [31m-[m
 .../documents/appengine.v1beta4.json               |   2469 [31m-[m
 .../documents/appengine.v1beta5.json               |   2439 [31m-[m
 .../discovery_cache/documents/apphub.v1.json       |   2471 [31m-[m
 .../discovery_cache/documents/apphub.v1alpha.json  |   2617 [31m-[m
 .../documents/area120tables.v1alpha1.json          |    998 [31m-[m
 .../discovery_cache/documents/areainsights.v1.json |    402 [31m-[m
 .../documents/artifactregistry.v1.json             |   4859 [31m-[m
 .../documents/artifactregistry.v1beta1.json        |   1726 [31m-[m
 .../documents/artifactregistry.v1beta2.json        |   2396 [31m-[m
 .../documents/assuredworkloads.v1.json             |   2224 [31m-[m
 .../documents/assuredworkloads.v1beta1.json        |   2262 [31m-[m
 .../documents/authorizedbuyersmarketplace.v1.json  |   3306 [31m-[m
 .../authorizedbuyersmarketplace.v1alpha.json       |   3561 [31m-[m
 .../authorizedbuyersmarketplace.v1beta.json        |    397 [31m-[m
 .../discovery_cache/documents/backupdr.v1.json     |   6499 [31m-[m
 .../documents/baremetalsolution.v1.json            |    331 [31m-[m
 .../documents/baremetalsolution.v1alpha1.json      |    588 [31m-[m
 .../documents/baremetalsolution.v2.json            |   3959 [31m-[m
 .../discovery_cache/documents/batch.v1.json        |   2407 [31m-[m
 .../discovery_cache/documents/beyondcorp.v1.json   |   4105 [31m-[m
 .../documents/beyondcorp.v1alpha.json              |   6624 [31m-[m
 .../discovery_cache/documents/biglake.v1.json      |   1182 [31m-[m
 .../discovery_cache/documents/bigquery.v2.json     |  11331 [31m--[m
 .../documents/bigqueryconnection.v1.json           |   1020 [31m-[m
 .../documents/bigqueryconnection.v1beta1.json      |    725 [31m-[m
 .../documents/bigquerydatapolicy.v1.json           |    715 [31m-[m
 .../documents/bigquerydatapolicy.v2.json           |    802 [31m-[m
 .../documents/bigquerydatatransfer.v1.json         |   2389 [31m-[m
 .../documents/bigqueryreservation.v1.json          |   2131 [31m-[m
 .../documents/bigqueryreservation.v1alpha2.json    |    904 [31m-[m
 .../documents/bigqueryreservation.v1beta1.json     |   1181 [31m-[m
 .../documents/bigtableadmin.v1.json                |    762 [31m-[m
 .../documents/bigtableadmin.v2.json                |   5999 [31m-[m
 .../documents/billingbudgets.v1.json               |    585 [31m-[m
 .../documents/billingbudgets.v1beta1.json          |    606 [31m-[m
 .../documents/binaryauthorization.v1.json          |   1930 [31m-[m
 .../documents/binaryauthorization.v1beta1.json     |   1055 [31m-[m
 .../documents/blockchainnodeengine.v1.json         |   1003 [31m-[m
 .../discovery_cache/documents/blogger.v2.json      |   1140 [31m-[m
 .../discovery_cache/documents/blogger.v3.json      |   2556 [31m-[m
 .../discovery_cache/documents/books.v1.json        |   5012 [31m-[m
 .../documents/businessprofileperformance.v1.json   |    721 [31m-[m
 .../discovery_cache/documents/calendar.v3.json     |   3270 [31m-[m
 .../documents/certificatemanager.v1.json           |   2456 [31m-[m
 .../discovery_cache/documents/chat.v1.json         |   5838 [31m-[m
 .../discovery_cache/documents/checks.v1alpha.json  |   2501 [31m-[m
 .../documents/chromemanagement.v1.json             |   6687 [31m-[m
 .../discovery_cache/documents/chromepolicy.v1.json |   1845 [31m-[m
 .../documents/chromeuxreport.v1.json               |    555 [31m-[m
 .../documents/chromewebstore.v1.1.json             |    374 [31m-[m
 .../documents/chromewebstore.v2.json               |    550 [31m-[m
 .../discovery_cache/documents/civicinfo.v2.json    |   1024 [31m-[m
 .../discovery_cache/documents/classroom.v1.json    |   6252 [31m-[m
 .../discovery_cache/documents/cloudasset.v1.json   |   4826 [31m-[m
 .../documents/cloudasset.v1beta1.json              |   1713 [31m-[m
 .../documents/cloudasset.v1p1beta1.json            |   1396 [31m-[m
 .../documents/cloudasset.v1p4beta1.json            |   1618 [31m-[m
 .../documents/cloudasset.v1p5beta1.json            |   1334 [31m-[m
 .../documents/cloudasset.v1p7beta1.json            |   1407 [31m-[m
 .../discovery_cache/documents/cloudbilling.v1.json |   1337 [31m-[m
 .../documents/cloudbilling.v1beta.json             |   1694 [31m-[m
 .../discovery_cache/documents/cloudbuild.v1.json   |   5959 [31m-[m
 .../documents/cloudbuild.v1alpha1.json             |   2432 [31m-[m
 .../documents/cloudbuild.v1alpha2.json             |   2406 [31m-[m
 .../documents/cloudbuild.v1beta1.json              |   2432 [31m-[m
 .../discovery_cache/documents/cloudbuild.v2.json   |   3454 [31m-[m
 .../discovery_cache/documents/cloudchannel.v1.json |   6121 [31m-[m
 .../documents/cloudcommerceprocurement.v1.json     |    949 [31m-[m
 .../documents/cloudcontrolspartner.v1.json         |   1400 [31m-[m
 .../documents/cloudcontrolspartner.v1beta.json     |   1400 [31m-[m
 .../documents/clouddebugger.v2.json                |   1130 [31m-[m
 .../discovery_cache/documents/clouddeploy.v1.json  |   7341 [31m--[m
 .../documents/clouderrorreporting.v1beta1.json     |   1084 [31m-[m
 .../documents/cloudfunctions.v1.json               |   1437 [31m-[m
 .../documents/cloudfunctions.v2.json               |   2188 [31m-[m
 .../documents/cloudfunctions.v2alpha.json          |   2231 [31m-[m
 .../documents/cloudfunctions.v2beta.json           |   2231 [31m-[m
 .../documents/cloudidentity.v1.json                |   4757 [31m-[m
 .../documents/cloudidentity.v1beta1.json           |   5768 [31m-[m
 .../discovery_cache/documents/cloudiot.v1.json     |   1693 [31m-[m
 .../discovery_cache/documents/cloudkms.v1.json     |   4870 [31m-[m
 .../documents/cloudlocationfinder.v1.json          |    472 [31m-[m
 .../documents/cloudlocationfinder.v1alpha.json     |    472 [31m-[m
 .../documents/cloudprofiler.v2.json                |    411 [31m-[m
 .../documents/cloudresourcemanager.v1.json         |   2309 [31m-[m
 .../documents/cloudresourcemanager.v1beta1.json    |   1287 [31m-[m
 .../documents/cloudresourcemanager.v2.json         |   1157 [31m-[m
 .../documents/cloudresourcemanager.v2beta1.json    |   1157 [31m-[m
 .../documents/cloudresourcemanager.v3.json         |   3286 [31m-[m
 .../documents/cloudscheduler.v1.json               |   1205 [31m-[m
 .../documents/cloudscheduler.v1beta1.json          |   1155 [31m-[m
 .../discovery_cache/documents/cloudsearch.v1.json  |   8017 [31m--[m
 .../discovery_cache/documents/cloudshell.v1.json   |    706 [31m-[m
 .../documents/cloudshell.v1alpha1.json             |    578 [31m-[m
 .../discovery_cache/documents/cloudsupport.v2.json |   1357 [31m-[m
 .../documents/cloudsupport.v2beta.json             |   1629 [31m-[m
 .../discovery_cache/documents/cloudtasks.v2.json   |   1696 [31m-[m
 .../documents/cloudtasks.v2beta2.json              |   2057 [31m-[m
 .../documents/cloudtasks.v2beta3.json              |   1805 [31m-[m
 .../discovery_cache/documents/cloudtrace.v1.json   |    380 [31m-[m
 .../discovery_cache/documents/cloudtrace.v2.json   |    610 [31m-[m
 .../documents/cloudtrace.v2beta1.json              |    339 [31m-[m
 .../discovery_cache/documents/composer.v1.json     |   2825 [31m-[m
 .../documents/composer.v1beta1.json                |   2840 [31m-[m
 .../discovery_cache/documents/compute.alpha.json   | 123687 [31m------------------[m
 .../discovery_cache/documents/compute.beta.json    | 110431 [31m----------------[m
 .../discovery_cache/documents/compute.v1.json      |  97441 [31m--------------[m
 .../discovery_cache/documents/config.v1.json       |   3166 [31m-[m
 .../discovery_cache/documents/connectors.v1.json   |   9036 [31m--[m
 .../discovery_cache/documents/connectors.v2.json   |   3021 [31m-[m
 .../contactcenteraiplatform.v1alpha1.json          |   1373 [31m-[m
 .../documents/contactcenterinsights.v1.json        |  14390 [31m--[m
 .../discovery_cache/documents/container.v1.json    |   9421 [31m--[m
 .../documents/container.v1beta1.json               |  10189 [31m--[m
 .../documents/containeranalysis.v1.json            |   7243 [31m-[m
 .../documents/containeranalysis.v1alpha1.json      |   7583 [31m--[m
 .../documents/containeranalysis.v1beta1.json       |   7449 [31m--[m
 .../discovery_cache/documents/content.v2.1.json    |  14315 [31m--[m
 .../discovery_cache/documents/content.v2.json      |  10116 [31m--[m
 .../documents/contentwarehouse.v1.json             |   5896 [31m-[m
 .../discovery_cache/documents/css.v1.json          |   1432 [31m-[m
 .../discovery_cache/documents/customsearch.v1.json |   1480 [31m-[m
 .../discovery_cache/documents/datacatalog.v1.json  |   5042 [31m-[m
 .../documents/datacatalog.v1beta1.json             |   4635 [31m-[m
 .../discovery_cache/documents/dataflow.v1b3.json   |   8315 [31m--[m
 .../discovery_cache/documents/dataform.v1.json     |   4918 [31m-[m
 .../documents/dataform.v1beta1.json                |   4918 [31m-[m
 .../discovery_cache/documents/datafusion.v1.json   |   1732 [31m-[m
 .../documents/datafusion.v1beta1.json              |   1996 [31m-[m
 .../documents/datalabeling.v1beta1.json            |   5660 [31m-[m
 .../discovery_cache/documents/datalineage.v1.json  |   1626 [31m-[m
 .../discovery_cache/documents/datamanager.v1.json  |   1315 [31m-[m
 .../documents/datamigration.v1.json                |   7196 [31m-[m
 .../documents/datamigration.v1beta1.json           |   2204 [31m-[m
 .../documents/datapipelines.v1.json                |   1024 [31m-[m
 .../discovery_cache/documents/dataplex.v1.json     |  14508 [31m--[m
 .../documents/dataportability.v1.json              |   1016 [31m-[m
 .../documents/dataportability.v1beta.json          |   1016 [31m-[m
 .../discovery_cache/documents/dataproc.v1.json     |  13082 [31m--[m
 .../documents/dataproc.v1beta2.json                |   4797 [31m-[m
 .../discovery_cache/documents/datastore.v1.json    |   3232 [31m-[m
 .../documents/datastore.v1beta1.json               |   1255 [31m-[m
 .../documents/datastore.v1beta3.json               |   2613 [31m-[m
 .../discovery_cache/documents/datastream.v1.json   |   4209 [31m-[m
 .../documents/datastream.v1alpha1.json             |   2737 [31m-[m
 .../documents/deploymentmanager.alpha.json         |   4031 [31m-[m
 .../documents/deploymentmanager.v2.json            |   2689 [31m-[m
 .../documents/deploymentmanager.v2beta.json        |   3884 [31m-[m
 .../documents/developerconnect.v1.json             |   3038 [31m-[m
 .../documents/dfareporting.v3.3.json               |  19978 [31m---[m
 .../documents/dfareporting.v3.4.json               |  20725 [31m---[m
 .../documents/dfareporting.v3.5.json               |    729 [31m-[m
 .../discovery_cache/documents/dfareporting.v4.json |  23291 [31m----[m
 .../discovery_cache/documents/dfareporting.v5.json |  22162 [31m----[m
 .../discovery_cache/documents/dialogflow.v2.json   |  25857 [31m----[m
 .../documents/dialogflow.v2beta1.json              |  25570 [31m----[m
 .../discovery_cache/documents/dialogflow.v3.json   |  21306 [31m---[m
 .../documents/dialogflow.v3beta1.json              |  22555 [31m----[m
 .../documents/digitalassetlinks.v1.json            |    513 [31m-[m
 .../discovery_cache/documents/discovery.v1.json    |    738 [31m-[m
 .../documents/discoveryengine.v1.json              |  29653 [31m-----[m
 .../documents/discoveryengine.v1alpha.json         |  35853 [31m-----[m
 .../documents/discoveryengine.v1beta.json          |  30834 [31m-----[m
 .../discovery_cache/documents/displayvideo.v1.json |  18848 [31m---[m
 .../discovery_cache/documents/displayvideo.v2.json |  21320 [31m---[m
 .../discovery_cache/documents/displayvideo.v3.json |  23756 [31m----[m
 .../discovery_cache/documents/displayvideo.v4.json |  24719 [31m----[m
 .../discovery_cache/documents/dlp.v2.json          |  13188 [31m--[m
 .../discovery_cache/documents/dns.v1.json          |   3544 [31m-[m
 .../discovery_cache/documents/dns.v1beta2.json     |   3544 [31m-[m
 .../discovery_cache/documents/dns.v2.json          |   3377 [31m-[m
 .../discovery_cache/documents/docs.v1.json         |   4653 [31m-[m
 .../discovery_cache/documents/documentai.v1.json   |   8724 [31m--[m
 .../documents/documentai.v1beta2.json              |   6139 [31m-[m
 .../documents/documentai.v1beta3.json              |   8913 [31m--[m
 .../discovery_cache/documents/domains.v1.json      |   2766 [31m-[m
 .../documents/domains.v1alpha2.json                |   2781 [31m-[m
 .../discovery_cache/documents/domains.v1beta1.json |   2766 [31m-[m
 .../discovery_cache/documents/domainsrdap.v1.json  |    436 [31m-[m
 .../documents/doubleclickbidmanager.v1.1.json      |   3779 [31m-[m
 .../documents/doubleclickbidmanager.v1.json        |    105 [31m-[m
 .../documents/doubleclickbidmanager.v2.json        |    777 [31m-[m
 .../documents/doubleclicksearch.v2.json            |   1230 [31m-[m
 .../discovery_cache/documents/drive.v2.json        |   6795 [31m-[m
 .../discovery_cache/documents/drive.v3.json        |   5289 [31m-[m
 .../documents/driveactivity.v2.json                |   1461 [31m-[m
 .../discovery_cache/documents/drivelabels.v2.json  |   3120 [31m-[m
 .../documents/drivelabels.v2beta.json              |   3120 [31m-[m
 .../documents/essentialcontacts.v1.json            |   1013 [31m-[m
 .../discovery_cache/documents/eventarc.v1.json     |   4112 [31m-[m
 .../documents/eventarc.v1beta1.json                |   1103 [31m-[m
 .../documents/factchecktools.v1alpha1.json         |    648 [31m-[m
 .../discovery_cache/documents/fcm.v1.json          |    631 [31m-[m
 .../discovery_cache/documents/fcmdata.v1beta1.json |    384 [31m-[m
 .../discovery_cache/documents/file.v1.json         |   2528 [31m-[m
 .../discovery_cache/documents/file.v1beta1.json    |   2924 [31m-[m
 .../documents/firebase.v1beta1.json                |   2373 [31m-[m
 .../documents/firebaseappcheck.v1.json             |   2483 [31m-[m
 .../documents/firebaseappcheck.v1beta.json         |   2762 [31m-[m
 .../documents/firebaseappdistribution.v1.json      |   1966 [31m-[m
 .../documents/firebaseappdistribution.v1alpha.json |   2280 [31m-[m
 .../documents/firebaseapphosting.v1.json           |   2711 [31m-[m
 .../documents/firebaseapphosting.v1beta.json       |   2737 [31m-[m
 .../documents/firebasedatabase.v1beta.json         |    450 [31m-[m
 .../documents/firebasedataconnect.v1.json          |   2068 [31m-[m
 .../documents/firebasedataconnect.v1beta.json      |   2068 [31m-[m
 .../documents/firebasedynamiclinks.v1.json         |   1049 [31m-[m
 .../documents/firebasehosting.v1.json              |    673 [31m-[m
 .../documents/firebasehosting.v1beta1.json         |   3885 [31m-[m
 .../discovery_cache/documents/firebaseml.v1.json   |    343 [31m-[m
 .../documents/firebaseml.v1beta2.json              |    572 [31m-[m
 .../documents/firebaseml.v2beta.json               |   2930 [31m-[m
 .../documents/firebaserules.v1.json                |   1063 [31m-[m
 .../documents/firebasestorage.v1beta.json          |    408 [31m-[m
 .../discovery_cache/documents/firestore.v1.json    |   5645 [31m-[m
 .../documents/firestore.v1beta1.json               |   3562 [31m-[m
 .../documents/firestore.v1beta2.json               |   1671 [31m-[m
 .../discovery_cache/documents/fitness.v1.json      |   1682 [31m-[m
 .../discovery_cache/documents/forms.v1.json        |   1765 [31m-[m
 .../discovery_cache/documents/games.v1.json        |   3628 [31m-[m
 .../gamesConfiguration.v1configuration.json        |    711 [31m-[m
 .../documents/gamesManagement.v1management.json    |    782 [31m-[m
 .../discovery_cache/documents/gameservices.v1.json |   1007 [31m-[m
 .../documents/gameservices.v1beta.json             |   1007 [31m-[m
 .../discovery_cache/documents/genomics.v1.json     |    796 [31m-[m
 .../documents/genomics.v1alpha2.json               |   1293 [31m-[m
 .../documents/genomics.v2alpha1.json               |   1257 [31m-[m
 .../discovery_cache/documents/gkebackup.v1.json    |   4675 [31m-[m
 .../discovery_cache/documents/gkehub.v1.json       |   6706 [31m-[m
 .../discovery_cache/documents/gkehub.v1alpha.json  |   7691 [31m--[m
 .../discovery_cache/documents/gkehub.v1alpha2.json |   1517 [31m-[m
 .../discovery_cache/documents/gkehub.v1beta.json   |   6832 [31m-[m
 .../discovery_cache/documents/gkehub.v1beta1.json  |   1632 [31m-[m
 .../discovery_cache/documents/gkehub.v2.json       |   3471 [31m-[m
 .../discovery_cache/documents/gkehub.v2alpha.json  |   3471 [31m-[m
 .../discovery_cache/documents/gkehub.v2beta.json   |   3471 [31m-[m
 .../discovery_cache/documents/gkeonprem.v1.json    |   6992 [31m-[m
 .../discovery_cache/documents/gmail.v1.json        |   4444 [31m-[m
 .../documents/gmailpostmastertools.v1.json         |    543 [31m-[m
 .../documents/gmailpostmastertools.v1beta1.json    |    549 [31m-[m
 .../documents/groupsmigration.v1.json              |    171 [31m-[m
 .../documents/groupssettings.v1.json               |    419 [31m-[m
 .../discovery_cache/documents/healthcare.v1.json   |   8982 [31m--[m
 .../documents/healthcare.v1beta1.json              |  10093 [31m--[m
 .../discovery_cache/documents/homegraph.v1.json    |    598 [31m-[m
 .../discovery_cache/documents/iam.v1.json          |   6822 [31m-[m
 .../discovery_cache/documents/iam.v2.json          |    880 [31m-[m
 .../discovery_cache/documents/iam.v2beta.json      |    880 [31m-[m
 .../documents/iamcredentials.v1.json               |    408 [31m-[m
 .../discovery_cache/documents/iap.v1.json          |   1421 [31m-[m
 .../discovery_cache/documents/iap.v1beta1.json     |    336 [31m-[m
 .../discovery_cache/documents/ideahub.v1alpha.json |    518 [31m-[m
 .../discovery_cache/documents/ideahub.v1beta.json  |    475 [31m-[m
 .../documents/identitytoolkit.v1.json              |   3906 [31m-[m
 .../documents/identitytoolkit.v2.json              |   3939 [31m-[m
 .../documents/identitytoolkit.v3.json              |   2115 [31m-[m
 .../discovery_cache/documents/ids.v1.json          |    837 [31m-[m
 .../discovery_cache/documents/index.json           |   4574 [31m-[m
 .../discovery_cache/documents/indexing.v3.json     |    220 [31m-[m
 .../discovery_cache/documents/integrations.v1.json |  15063 [31m---[m
 .../documents/integrations.v1alpha.json            |  11961 [31m--[m
 .../discovery_cache/documents/jobs.v2.json         |   4173 [31m-[m
 .../discovery_cache/documents/jobs.v3.json         |   2676 [31m-[m
 .../discovery_cache/documents/jobs.v3p1beta1.json  |   2860 [31m-[m
 .../discovery_cache/documents/jobs.v4.json         |   2924 [31m-[m
 .../discovery_cache/documents/keep.v1.json         |    623 [31m-[m
 .../discovery_cache/documents/kgsearch.v1.json     |    184 [31m-[m
 .../discovery_cache/documents/kmsinventory.v1.json |    933 [31m-[m
 .../discovery_cache/documents/language.v1.json     |   5919 [31m-[m
 .../documents/language.v1beta1.json                |   1100 [31m-[m
 .../documents/language.v1beta2.json                |   5937 [31m-[m
 .../discovery_cache/documents/language.v2.json     |   5290 [31m-[m
 .../discovery_cache/documents/libraryagent.v1.json |    364 [31m-[m
 .../discovery_cache/documents/licensing.v1.json    |    513 [31m-[m
 .../documents/lifesciences.v2beta.json             |   1225 [31m-[m
 .../documents/localservices.v1.json                |    586 [31m-[m
 .../discovery_cache/documents/logging.v2.json      |  11760 [31m--[m
 .../discovery_cache/documents/looker.v1.json       |   1669 [31m-[m
 .../documents/managedidentities.v1.json            |   3235 [31m-[m
 .../documents/managedidentities.v1alpha1.json      |   3221 [31m-[m
 .../documents/managedidentities.v1beta1.json       |   3247 [31m-[m
 .../discovery_cache/documents/managedkafka.v1.json |   4364 [31m-[m
 .../documents/manufacturers.v1.json                |   1418 [31m-[m
 .../documents/marketingplatformadmin.v1alpha.json  |    682 [31m-[m
 .../discovery_cache/documents/meet.v2.json         |   1332 [31m-[m
 .../discovery_cache/documents/memcache.v1.json     |   1962 [31m-[m
 .../documents/memcache.v1beta2.json                |   2018 [31m-[m
 .../documents/merchantapi.accounts_v1.json         |   5628 [31m-[m
 .../documents/merchantapi.accounts_v1beta.json     |   5489 [31m-[m
 .../documents/merchantapi.conversions_v1.json      |    650 [31m-[m
 .../documents/merchantapi.conversions_v1beta.json  |    650 [31m-[m
 .../documents/merchantapi.datasources_v1.json      |   1037 [31m-[m
 .../documents/merchantapi.datasources_v1beta.json  |   1049 [31m-[m
 .../documents/merchantapi.inventories_v1.json      |    713 [31m-[m
 .../documents/merchantapi.inventories_v1beta.json  |    667 [31m-[m
 .../documents/merchantapi.issueresolution_v1.json  |   1250 [31m-[m
 .../merchantapi.issueresolution_v1beta.json        |   1250 [31m-[m
 .../documents/merchantapi.lfp_v1.json              |    902 [31m-[m
 .../documents/merchantapi.lfp_v1beta.json          |    902 [31m-[m
 .../documents/merchantapi.notifications_v1.json    |    483 [31m-[m
 .../merchantapi.notifications_v1beta.json          |    483 [31m-[m
 .../documents/merchantapi.ordertracking_v1.json    |    569 [31m-[m
 .../merchantapi.ordertracking_v1beta.json          |    574 [31m-[m
 .../documents/merchantapi.products_v1.json         |   2446 [31m-[m
 .../documents/merchantapi.products_v1beta.json     |   1859 [31m-[m
 .../documents/merchantapi.promotions_v1.json       |   1034 [31m-[m
 .../documents/merchantapi.promotions_v1beta.json   |   1034 [31m-[m
 .../documents/merchantapi.quota_v1.json            |    393 [31m-[m
 .../documents/merchantapi.quota_v1beta.json        |    393 [31m-[m
 .../documents/merchantapi.reports_v1.json          |   1550 [31m-[m
 .../documents/merchantapi.reports_v1beta.json      |   1550 [31m-[m
 .../documents/merchantapi.reviews_v1beta.json      |   1400 [31m-[m
 .../discovery_cache/documents/metastore.v1.json    |   3641 [31m-[m
 .../documents/metastore.v1alpha.json               |   3902 [31m-[m
 .../documents/metastore.v1beta.json                |   3902 [31m-[m
 .../discovery_cache/documents/metastore.v2.json    |   1837 [31m-[m
 .../documents/metastore.v2alpha.json               |   2337 [31m-[m
 .../documents/metastore.v2beta.json                |   2337 [31m-[m
 .../documents/migrationcenter.v1.json              |   7277 [31m--[m
 .../documents/migrationcenter.v1alpha1.json        |   9541 [31m--[m
 .../discovery_cache/documents/ml.v1.json           |   3914 [31m-[m
 .../discovery_cache/documents/monitoring.v1.json   |   3104 [31m-[m
 .../discovery_cache/documents/monitoring.v3.json   |   6549 [31m-[m
 .../documents/mybusinessaccountmanagement.v1.json  |    935 [31m-[m
 .../documents/mybusinessbusinesscalls.v1.json      |    398 [31m-[m
 .../mybusinessbusinessinformation.v1.json          |   1806 [31m-[m
 .../documents/mybusinesslodging.v1.json            |   6240 [31m-[m
 .../documents/mybusinessnotifications.v1.json      |    229 [31m-[m
 .../documents/mybusinessplaceactions.v1.json       |    448 [31m-[m
 .../documents/mybusinessqanda.v1.json              |    519 [31m-[m
 .../documents/mybusinessverifications.v1.json      |    763 [31m-[m
 .../discovery_cache/documents/netapp.v1.json       |   5153 [31m-[m
 .../discovery_cache/documents/netapp.v1beta1.json  |   5207 [31m-[m
 .../documents/networkconnectivity.v1.json          |   7033 [31m-[m
 .../documents/networkconnectivity.v1alpha1.json    |   1918 [31m-[m
 .../documents/networkmanagement.v1.json            |   4494 [31m-[m
 .../documents/networkmanagement.v1beta1.json       |   4506 [31m-[m
 .../documents/networksecurity.v1.json              |   8543 [31m--[m
 .../documents/networksecurity.v1beta1.json         |   9387 [31m--[m
 .../documents/networkservices.v1.json              |   6358 [31m-[m
 .../documents/networkservices.v1beta1.json         |   6194 [31m-[m
 .../discovery_cache/documents/notebooks.v1.json    |   4620 [31m-[m
 .../discovery_cache/documents/notebooks.v2.json    |   2326 [31m-[m
 .../discovery_cache/documents/oauth2.v2.json       |    293 [31m-[m
 .../documents/observability.v1.json                |    819 [31m-[m
 .../documents/ondemandscanning.v1.json             |   3319 [31m-[m
 .../documents/ondemandscanning.v1beta1.json        |   3314 [31m-[m
 .../documents/oracledatabase.v1.json               |   7141 [31m-[m
 .../discovery_cache/documents/orgpolicy.v2.json    |   1431 [31m-[m
 .../discovery_cache/documents/osconfig.v1.json     |   4031 [31m-[m
 .../documents/osconfig.v1alpha.json                |   2890 [31m-[m
 .../discovery_cache/documents/osconfig.v1beta.json |   2685 [31m-[m
 .../discovery_cache/documents/osconfig.v2.json     |   2376 [31m-[m
 .../discovery_cache/documents/osconfig.v2beta.json |   2376 [31m-[m
 .../discovery_cache/documents/oslogin.v1.json      |    567 [31m-[m
 .../discovery_cache/documents/oslogin.v1alpha.json |    814 [31m-[m
 .../discovery_cache/documents/oslogin.v1beta.json  |    784 [31m-[m
 .../documents/pagespeedonline.v5.json              |   1008 [31m-[m
 .../documents/parallelstore.v1.json                |   1098 [31m-[m
 .../documents/parallelstore.v1beta.json            |   1089 [31m-[m
 .../documents/parametermanager.v1.json             |   1082 [31m-[m
 .../documents/paymentsresellersubscription.v1.json |   1866 [31m-[m
 .../discovery_cache/documents/people.v1.json       |   3313 [31m-[m
 .../discovery_cache/documents/places.v1.json       |   2518 [31m-[m
 .../documents/playablelocations.v3.json            |    528 [31m-[m
 .../documents/playcustomapp.v1.json                |    210 [31m-[m
 .../documents/playdeveloperreporting.v1alpha1.json |   2341 [31m-[m
 .../documents/playdeveloperreporting.v1beta1.json  |   2341 [31m-[m
 .../documents/playgrouping.v1alpha1.json           |    262 [31m-[m
 .../documents/playintegrity.v1.json                |    759 [31m-[m
 .../documents/policyanalyzer.v1.json               |    350 [31m-[m
 .../documents/policyanalyzer.v1beta1.json          |    350 [31m-[m
 .../documents/policysimulator.v1.json              |   2432 [31m-[m
 .../documents/policysimulator.v1alpha.json         |   1450 [31m-[m
 .../documents/policysimulator.v1beta.json          |   2539 [31m-[m
 .../documents/policysimulator.v1beta1.json         |    984 [31m-[m
 .../documents/policytroubleshooter.v1.json         |    536 [31m-[m
 .../documents/policytroubleshooter.v1beta.json     |    502 [31m-[m
 .../discovery_cache/documents/pollen.v1.json       |    566 [31m-[m
 .../discovery_cache/documents/poly.v1.json         |    805 [31m-[m
 .../discovery_cache/documents/privateca.v1.json    |   3633 [31m-[m
 .../documents/privateca.v1beta1.json               |    921 [31m-[m
 .../documents/prod_tt_sasportal.v1alpha1.json      |   3774 [31m-[m
 .../discovery_cache/documents/publicca.v1.json     |    180 [31m-[m
 .../documents/publicca.v1alpha1.json               |    180 [31m-[m
 .../documents/publicca.v1beta1.json                |    180 [31m-[m
 .../discovery_cache/documents/pubsub.v1.json       |   3172 [31m-[m
 .../discovery_cache/documents/pubsub.v1beta1a.json |    880 [31m-[m
 .../discovery_cache/documents/pubsub.v1beta2.json  |   1206 [31m-[m
 .../discovery_cache/documents/pubsublite.v1.json   |   1708 [31m-[m
 .../documents/rapidmigrationassessment.v1.json     |   1065 [31m-[m
 .../readerrevenuesubscriptionlinking.v1.json       |    300 [31m-[m
 .../documents/realtimebidding.v1.json              |   3349 [31m-[m
 .../documents/realtimebidding.v1alpha.json         |    319 [31m-[m
 .../documents/recaptchaenterprise.v1.json          |   2675 [31m-[m
 .../documents/recommendationengine.v1beta1.json    |   2065 [31m-[m
 .../discovery_cache/documents/recommender.v1.json  |   2457 [31m-[m
 .../documents/recommender.v1beta1.json             |   2839 [31m-[m
 .../discovery_cache/documents/redis.v1.json        |   5331 [31m-[m
 .../discovery_cache/documents/redis.v1beta1.json   |   5338 [31m-[m
 .../documents/remotebuildexecution.v1.json         |   2103 [31m-[m
 .../documents/remotebuildexecution.v1alpha.json    |   2187 [31m-[m
 .../documents/remotebuildexecution.v2.json         |   2623 [31m-[m
 .../discovery_cache/documents/reseller.v1.json     |   1038 [31m-[m
 .../documents/resourcesettings.v1.json             |    685 [31m-[m
 .../discovery_cache/documents/retail.v2.json       |   8440 [31m--[m
 .../discovery_cache/documents/retail.v2alpha.json  |   9522 [31m--[m
 .../discovery_cache/documents/retail.v2beta.json   |   8804 [31m--[m
 .../discovery_cache/documents/run.v1.json          |   6999 [31m-[m
 .../discovery_cache/documents/run.v1alpha1.json    |   1286 [31m-[m
 .../discovery_cache/documents/run.v1beta1.json     |    898 [31m-[m
 .../discovery_cache/documents/run.v2.json          |   6728 [31m-[m
 .../documents/runtimeconfig.v1.json                |    313 [31m-[m
 .../documents/runtimeconfig.v1beta1.json           |   1176 [31m-[m
 .../documents/saasservicemgmt.v1beta1.json         |   3690 [31m-[m
 .../discovery_cache/documents/safebrowsing.v4.json |   1344 [31m-[m
 .../discovery_cache/documents/safebrowsing.v5.json |    604 [31m-[m
 .../documents/sasportal.v1alpha1.json              |   3773 [31m-[m
 .../discovery_cache/documents/script.v1.json       |   1694 [31m-[m
 .../discovery_cache/documents/searchads360.v0.json |   9020 [31m--[m
 .../documents/searchconsole.v1.json                |   1535 [31m-[m
 .../documents/secretmanager.v1.json                |   1985 [31m-[m
 .../documents/secretmanager.v1beta1.json           |   1293 [31m-[m
 .../documents/secretmanager.v1beta2.json           |   1985 [31m-[m
 .../documents/securesourcemanager.v1.json          |   3568 [31m-[m
 .../documents/securitycenter.v1.json               |  17011 [31m---[m
 .../documents/securitycenter.v1beta1.json          |  10996 [31m--[m
 .../documents/securitycenter.v1beta2.json          |  11723 [31m--[m
 .../documents/securityposture.v1.json              |   2154 [31m-[m
 .../documents/serviceconsumermanagement.v1.json    |   3490 [31m-[m
 .../serviceconsumermanagement.v1beta1.json         |   3616 [31m-[m
 .../documents/servicecontrol.v1.json               |   2323 [31m-[m
 .../documents/servicecontrol.v2.json               |   1340 [31m-[m
 .../documents/servicedirectory.v1.json             |   1259 [31m-[m
 .../documents/servicedirectory.v1beta1.json        |   1383 [31m-[m
 .../documents/servicemanagement.v1.json            |   3855 [31m-[m
 .../documents/servicenetworking.v1.json            |   4352 [31m-[m
 .../documents/servicenetworking.v1beta.json        |   3152 [31m-[m
 .../discovery_cache/documents/serviceusage.v1.json |   3862 [31m-[m
 .../documents/serviceusage.v1beta1.json            |   4750 [31m-[m
 .../discovery_cache/documents/sheets.v4.json       |   8314 [31m--[m
 .../documents/siteVerification.v1.json             |    321 [31m-[m
 .../discovery_cache/documents/slides.v1.json       |   4632 [31m-[m
 .../documents/smartdevicemanagement.v1.json        |    488 [31m-[m
 .../discovery_cache/documents/solar.v1.json        |    972 [31m-[m
 .../discovery_cache/documents/sourcerepo.v1.json   |    879 [31m-[m
 .../discovery_cache/documents/spanner.v1.json      |   8067 [31m--[m
 .../discovery_cache/documents/speech.v1.json       |   1549 [31m-[m
 .../documents/speech.v1p1beta1.json                |   1571 [31m-[m
 .../discovery_cache/documents/speech.v2beta1.json  |    407 [31m-[m
 .../discovery_cache/documents/sqladmin.v1.json     |   8645 [31m--[m
 .../documents/sqladmin.v1beta4.json                |   8644 [31m--[m
 .../discovery_cache/documents/storage.v1.json      |   6537 [31m-[m
 .../documents/storagebatchoperations.v1.json       |   1146 [31m-[m
 .../documents/storagetransfer.v1.json              |   2004 [31m-[m
 .../documents/streetviewpublish.v1.json            |   1333 [31m-[m
 .../discovery_cache/documents/sts.v1.json          |    560 [31m-[m
 .../discovery_cache/documents/sts.v1beta.json      |    555 [31m-[m
 .../discovery_cache/documents/tagmanager.v1.json   |   3241 [31m-[m
 .../discovery_cache/documents/tagmanager.v2.json   |   6568 [31m-[m
 .../discovery_cache/documents/tasks.v1.json        |    836 [31m-[m
 .../discovery_cache/documents/testing.v1.json      |   2924 [31m-[m
 .../discovery_cache/documents/texttospeech.v1.json |    883 [31m-[m
 .../documents/texttospeech.v1beta1.json            |    858 [31m-[m
 .../documents/toolresults.v1beta3.json             |   3935 [31m-[m
 .../discovery_cache/documents/tpu.v1.json          |   1231 [31m-[m
 .../discovery_cache/documents/tpu.v1alpha1.json    |   1241 [31m-[m
 .../discovery_cache/documents/tpu.v2.json          |   2155 [31m-[m
 .../discovery_cache/documents/tpu.v2alpha1.json    |   2607 [31m-[m
 .../documents/trafficdirector.v2.json              |   1183 [31m-[m
 .../documents/trafficdirector.v3.json              |   1590 [31m-[m
 .../discovery_cache/documents/transcoder.v1.json   |   2007 [31m-[m
 .../documents/transcoder.v1beta1.json              |   1506 [31m-[m
 .../discovery_cache/documents/translate.v2.json    |    440 [31m-[m
 .../discovery_cache/documents/translate.v3.json    |   3269 [31m-[m
 .../documents/translate.v3beta1.json               |   1532 [31m-[m
 .../documents/travelimpactmodel.v1.json            |    556 [31m-[m
 .../discovery_cache/documents/vault.v1.json        |   2934 [31m-[m
 .../discovery_cache/documents/vectortile.v1.json   |    907 [31m-[m
 .../documents/verifiedaccess.v1.json               |    238 [31m-[m
 .../documents/verifiedaccess.v2.json               |    635 [31m-[m
 .../documents/versionhistory.v1.json               |    534 [31m-[m
 .../documents/videointelligence.v1.json            |   5182 [31m-[m
 .../documents/videointelligence.v1beta2.json       |   4930 [31m-[m
 .../documents/videointelligence.v1p1beta1.json     |   4930 [31m-[m
 .../documents/videointelligence.v1p2beta1.json     |   4930 [31m-[m
 .../documents/videointelligence.v1p3beta1.json     |   4932 [31m-[m
 .../discovery_cache/documents/vision.v1.json       |   9422 [31m--[m
 .../documents/vision.v1p1beta1.json                |   8373 [31m--[m
 .../documents/vision.v1p2beta1.json                |   8373 [31m--[m
 .../discovery_cache/documents/vmmigration.v1.json  |   6881 [31m-[m
 .../documents/vmmigration.v1alpha1.json            |   7133 [31m-[m
 .../discovery_cache/documents/vmwareengine.v1.json |   6426 [31m-[m
 .../discovery_cache/documents/vpcaccess.v1.json    |    743 [31m-[m
 .../documents/vpcaccess.v1beta1.json               |    755 [31m-[m
 .../documents/walletobjects.v1.json                |   9839 [31m--[m
 .../discovery_cache/documents/webfonts.v1.json     |    306 [31m-[m
 .../discovery_cache/documents/webmasters.v3.json   |    555 [31m-[m
 .../discovery_cache/documents/webrisk.v1.json      |    791 [31m-[m
 .../documents/websecurityscanner.v1.json           |   1432 [31m-[m
 .../documents/websecurityscanner.v1alpha.json      |   1137 [31m-[m
 .../documents/websecurityscanner.v1beta.json       |   1387 [31m-[m
 .../documents/workflowexecutions.v1.json           |   1182 [31m-[m
 .../documents/workflowexecutions.v1beta.json       |    492 [31m-[m
 .../discovery_cache/documents/workflows.v1.json    |    889 [31m-[m
 .../documents/workflows.v1beta.json                |    731 [31m-[m
 .../documents/workloadmanager.v1.json              |   3512 [31m-[m
 .../documents/workspaceevents.v1.json              |    729 [31m-[m
 .../discovery_cache/documents/workstations.v1.json |   2600 [31m-[m
 .../documents/workstations.v1beta.json             |   2603 [31m-[m
 .../discovery_cache/documents/youtube.v3.json      |  12438 [31m--[m
 .../documents/youtubeAnalytics.v1.json             |    106 [31m-[m
 .../documents/youtubeAnalytics.v2.json             |    748 [31m-[m
 .../documents/youtubereporting.v1.json             |   1007 [31m-[m
 .../googleapiclient/discovery_cache/file_cache.py  |    145 [31m-[m
 .../Lib/site-packages/googleapiclient/errors.py    |    197 [31m-[m
 .../venv/Lib/site-packages/googleapiclient/http.py |   1962 [31m-[m
 .../Lib/site-packages/googleapiclient/mimeparse.py |    183 [31m-[m
 .../Lib/site-packages/googleapiclient/model.py     |    429 [31m-[m
 .../site-packages/googleapiclient/sample_tools.py  |    108 [31m-[m
 .../Lib/site-packages/googleapiclient/schema.py    |    317 [31m-[m
 .../Lib/site-packages/googleapiclient/version.py   |     15 [31m-[m
 .../INSTALLER                                      |      1 [31m-[m
 .../METADATA                                       |    227 [31m-[m
 .../RECORD                                         |    268 [31m-[m
 .../WHEEL                                          |      5 [31m-[m
 .../licenses/LICENSE                               |    202 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../greenlet-3.3.0.dist-info/INSTALLER             |      1 [31m-[m
 .../greenlet-3.3.0.dist-info/METADATA              |    117 [31m-[m
 .../site-packages/greenlet-3.3.0.dist-info/RECORD  |    121 [31m-[m
 .../site-packages/greenlet-3.3.0.dist-info/WHEEL   |      5 [31m-[m
 .../greenlet-3.3.0.dist-info/licenses/LICENSE      |     30 [31m-[m
 .../greenlet-3.3.0.dist-info/licenses/LICENSE.PSF  |     47 [31m-[m
 .../greenlet-3.3.0.dist-info/top_level.txt         |      1 [31m-[m
 .../venv/Lib/site-packages/greenlet/CObjects.cpp   |    157 [31m-[m
 .../venv/Lib/site-packages/greenlet/PyGreenlet.cpp |    774 [31m-[m
 .../venv/Lib/site-packages/greenlet/PyGreenlet.hpp |     35 [31m-[m
 .../greenlet/PyGreenletUnswitchable.cpp            |    147 [31m-[m
 .../venv/Lib/site-packages/greenlet/PyModule.cpp   |    292 [31m-[m
 .../Lib/site-packages/greenlet/TBrokenGreenlet.cpp |     45 [31m-[m
 .../Lib/site-packages/greenlet/TExceptionState.cpp |     62 [31m-[m
 .../venv/Lib/site-packages/greenlet/TGreenlet.cpp  |    719 [31m-[m
 .../venv/Lib/site-packages/greenlet/TGreenlet.hpp  |    837 [31m-[m
 .../site-packages/greenlet/TGreenletGlobals.cpp    |     94 [31m-[m
 .../Lib/site-packages/greenlet/TMainGreenlet.cpp   |    160 [31m-[m
 .../Lib/site-packages/greenlet/TPythonState.cpp    |    439 [31m-[m
 .../Lib/site-packages/greenlet/TStackState.cpp     |    265 [31m-[m
 .../Lib/site-packages/greenlet/TThreadState.hpp    |    523 [31m-[m
 .../site-packages/greenlet/TThreadStateCreator.hpp |    102 [31m-[m
 .../site-packages/greenlet/TThreadStateDestroy.cpp |    223 [31m-[m
 .../Lib/site-packages/greenlet/TUserGreenlet.cpp   |    662 [31m-[m
 .../venv/Lib/site-packages/greenlet/__init__.py    |     71 [31m-[m
 .../greenlet/__pycache__/__init__.cpython-312.pyc  |    Bin [31m1056[m -> [32m0[m bytes
 .../greenlet/_greenlet.cp312-win_amd64.pyd         |    Bin [31m220672[m -> [32m0[m bytes
 .../venv/Lib/site-packages/greenlet/greenlet.cpp   |    323 [31m-[m
 backend/venv/Lib/site-packages/greenlet/greenlet.h |    164 [31m-[m
 .../site-packages/greenlet/greenlet_allocator.hpp  |     76 [31m-[m
 .../greenlet/greenlet_compiler_compat.hpp          |     98 [31m-[m
 .../greenlet/greenlet_cpython_compat.hpp           |    150 [31m-[m
 .../site-packages/greenlet/greenlet_exceptions.hpp |    171 [31m-[m
 .../site-packages/greenlet/greenlet_internal.hpp   |    107 [31m-[m
 .../greenlet/greenlet_msvc_compat.hpp              |     91 [31m-[m
 .../Lib/site-packages/greenlet/greenlet_refs.hpp   |   1118 [31m-[m
 .../site-packages/greenlet/greenlet_slp_switch.hpp |    103 [31m-[m
 .../greenlet/greenlet_thread_support.hpp           |     31 [31m-[m
 .../site-packages/greenlet/platform/__init__.py    |      0
 .../platform/__pycache__/__init__.cpython-312.pyc  |    Bin [31m179[m -> [32m0[m bytes
 .../greenlet/platform/setup_switch_x64_masm.cmd    |      2 [31m-[m
 .../greenlet/platform/switch_aarch64_gcc.h         |    124 [31m-[m
 .../greenlet/platform/switch_alpha_unix.h          |     30 [31m-[m
 .../greenlet/platform/switch_amd64_unix.h          |     87 [31m-[m
 .../greenlet/platform/switch_arm32_gcc.h           |     79 [31m-[m
 .../greenlet/platform/switch_arm32_ios.h           |     67 [31m-[m
 .../greenlet/platform/switch_arm64_masm.asm        |     53 [31m-[m
 .../greenlet/platform/switch_arm64_masm.obj        |    Bin [31m746[m -> [32m0[m bytes
 .../greenlet/platform/switch_arm64_msvc.h          |     17 [31m-[m
 .../greenlet/platform/switch_csky_gcc.h            |     48 [31m-[m
 .../greenlet/platform/switch_loongarch64_linux.h   |     31 [31m-[m
 .../greenlet/platform/switch_m68k_gcc.h            |     38 [31m-[m
 .../greenlet/platform/switch_mips_unix.h           |     64 [31m-[m
 .../greenlet/platform/switch_ppc64_aix.h           |    103 [31m-[m
 .../greenlet/platform/switch_ppc64_linux.h         |    105 [31m-[m
 .../greenlet/platform/switch_ppc_aix.h             |     87 [31m-[m
 .../greenlet/platform/switch_ppc_linux.h           |     84 [31m-[m
 .../greenlet/platform/switch_ppc_macosx.h          |     82 [31m-[m
 .../greenlet/platform/switch_ppc_unix.h            |     82 [31m-[m
 .../greenlet/platform/switch_riscv_unix.h          |     41 [31m-[m
 .../greenlet/platform/switch_s390_unix.h           |     87 [31m-[m
 .../greenlet/platform/switch_sh_gcc.h              |     36 [31m-[m
 .../greenlet/platform/switch_sparc_sun_gcc.h       |     92 [31m-[m
 .../greenlet/platform/switch_x32_unix.h            |     63 [31m-[m
 .../greenlet/platform/switch_x64_masm.asm          |    111 [31m-[m
 .../greenlet/platform/switch_x64_masm.obj          |    Bin [31m1078[m -> [32m0[m bytes
 .../greenlet/platform/switch_x64_msvc.h            |     60 [31m-[m
 .../greenlet/platform/switch_x86_msvc.h            |    326 [31m-[m
 .../greenlet/platform/switch_x86_unix.h            |    105 [31m-[m
 .../site-packages/greenlet/slp_platformselect.h    |     77 [31m-[m
 .../Lib/site-packages/greenlet/tests/__init__.py   |    248 [31m-[m
 .../tests/__pycache__/__init__.cpython-312.pyc     |    Bin [31m9215[m -> [32m0[m bytes
 .../fail_clearing_run_switches.cpython-312.pyc     |    Bin [31m2064[m -> [32m0[m bytes
 .../__pycache__/fail_cpp_exception.cpython-312.pyc |    Bin [31m1599[m -> [32m0[m bytes
 ...ail_initialstub_already_started.cpython-312.pyc |    Bin [31m3467[m -> [32m0[m bytes
 .../__pycache__/fail_slp_switch.cpython-312.pyc    |    Bin [31m1292[m -> [32m0[m bytes
 .../fail_switch_three_greenlets.cpython-312.pyc    |    Bin [31m1708[m -> [32m0[m bytes
 .../fail_switch_three_greenlets2.cpython-312.pyc   |    Bin [31m2562[m -> [32m0[m bytes
 .../fail_switch_two_greenlets.cpython-312.pyc      |    Bin [31m1679[m -> [32m0[m bytes
 .../tests/__pycache__/leakcheck.cpython-312.pyc    |    Bin [31m11671[m -> [32m0[m bytes
 .../__pycache__/test_contextvars.cpython-312.pyc   |    Bin [31m15388[m -> [32m0[m bytes
 .../tests/__pycache__/test_cpp.cpython-312.pyc     |    Bin [31m4076[m -> [32m0[m bytes
 .../test_extension_interface.cpython-312.pyc       |    Bin [31m7436[m -> [32m0[m bytes
 .../tests/__pycache__/test_gc.cpython-312.pyc      |    Bin [31m4902[m -> [32m0[m bytes
 .../__pycache__/test_generator.cpython-312.pyc     |    Bin [31m3052[m -> [32m0[m bytes
 .../test_generator_nested.cpython-312.pyc          |    Bin [31m7746[m -> [32m0[m bytes
 .../__pycache__/test_greenlet.cpython-312.pyc      |    Bin [31m76136[m -> [32m0[m bytes
 .../test_greenlet_trash.cpython-312.pyc            |    Bin [31m6759[m -> [32m0[m bytes
 .../tests/__pycache__/test_leaks.cpython-312.pyc   |    Bin [31m19884[m -> [32m0[m bytes
 .../__pycache__/test_stack_saved.cpython-312.pyc   |    Bin [31m1331[m -> [32m0[m bytes
 .../tests/__pycache__/test_throw.cpython-312.pyc   |    Bin [31m7339[m -> [32m0[m bytes
 .../tests/__pycache__/test_tracing.cpython-312.pyc |    Bin [31m13825[m -> [32m0[m bytes
 .../tests/__pycache__/test_version.cpython-312.pyc |    Bin [31m2538[m -> [32m0[m bytes
 .../tests/__pycache__/test_weakref.cpython-312.pyc |    Bin [31m2722[m -> [32m0[m bytes
 .../site-packages/greenlet/tests/_test_extension.c |    258 [31m-[m
 .../tests/_test_extension.cp312-win_amd64.pyd      |    Bin [31m14336[m -> [32m0[m bytes
 .../tests/_test_extension_cpp.cp312-win_amd64.pyd  |    Bin [31m15872[m -> [32m0[m bytes
 .../greenlet/tests/_test_extension_cpp.cpp         |    229 [31m-[m
 .../greenlet/tests/fail_clearing_run_switches.py   |     47 [31m-[m
 .../greenlet/tests/fail_cpp_exception.py           |     33 [31m-[m
 .../tests/fail_initialstub_already_started.py      |     78 [31m-[m
 .../greenlet/tests/fail_slp_switch.py              |     29 [31m-[m
 .../greenlet/tests/fail_switch_three_greenlets.py  |     44 [31m-[m
 .../greenlet/tests/fail_switch_three_greenlets2.py |     55 [31m-[m
 .../greenlet/tests/fail_switch_two_greenlets.py    |     41 [31m-[m
 .../Lib/site-packages/greenlet/tests/leakcheck.py  |    336 [31m-[m
 .../greenlet/tests/test_contextvars.py             |    312 [31m-[m
 .../Lib/site-packages/greenlet/tests/test_cpp.py   |     73 [31m-[m
 .../greenlet/tests/test_extension_interface.py     |    115 [31m-[m
 .../Lib/site-packages/greenlet/tests/test_gc.py    |     86 [31m-[m
 .../site-packages/greenlet/tests/test_generator.py |     59 [31m-[m
 .../greenlet/tests/test_generator_nested.py        |    168 [31m-[m
 .../site-packages/greenlet/tests/test_greenlet.py  |   1365 [31m-[m
 .../greenlet/tests/test_greenlet_trash.py          |    187 [31m-[m
 .../Lib/site-packages/greenlet/tests/test_leaks.py |    457 [31m-[m
 .../greenlet/tests/test_stack_saved.py             |     19 [31m-[m
 .../Lib/site-packages/greenlet/tests/test_throw.py |    128 [31m-[m
 .../site-packages/greenlet/tests/test_tracing.py   |    299 [31m-[m
 .../site-packages/greenlet/tests/test_version.py   |     41 [31m-[m
 .../site-packages/greenlet/tests/test_weakref.py   |     35 [31m-[m
 .../site-packages/groq-1.0.0.dist-info/INSTALLER   |      1 [31m-[m
 .../site-packages/groq-1.0.0.dist-info/METADATA    |    520 [31m-[m
 .../Lib/site-packages/groq-1.0.0.dist-info/RECORD  |    192 [31m-[m
 .../site-packages/groq-1.0.0.dist-info/REQUESTED   |      0
 .../Lib/site-packages/groq-1.0.0.dist-info/WHEEL   |      4 [31m-[m
 .../groq-1.0.0.dist-info/licenses/LICENSE          |    201 [31m-[m
 backend/venv/Lib/site-packages/groq/__init__.py    |     92 [31m-[m
 .../groq/__pycache__/__init__.cpython-312.pyc      |    Bin [31m2218[m -> [32m0[m bytes
 .../groq/__pycache__/_base_client.cpython-312.pyc  |    Bin [31m72267[m -> [32m0[m bytes
 .../groq/__pycache__/_client.cpython-312.pyc       |    Bin [31m23833[m -> [32m0[m bytes
 .../groq/__pycache__/_compat.cpython-312.pyc       |    Bin [31m7684[m -> [32m0[m bytes
 .../groq/__pycache__/_constants.cpython-312.pyc    |    Bin [31m696[m -> [32m0[m bytes
 .../groq/__pycache__/_exceptions.cpython-312.pyc   |    Bin [31m4948[m -> [32m0[m bytes
 .../groq/__pycache__/_files.cpython-312.pyc        |    Bin [31m6113[m -> [32m0[m bytes
 .../groq/__pycache__/_models.cpython-312.pyc       |    Bin [31m31745[m -> [32m0[m bytes
 .../groq/__pycache__/_qs.cpython-312.pyc           |    Bin [31m5786[m -> [32m0[m bytes
 .../groq/__pycache__/_resource.cpython-312.pyc     |    Bin [31m2124[m -> [32m0[m bytes
 .../groq/__pycache__/_response.cpython-312.pyc     |    Bin [31m36052[m -> [32m0[m bytes
 .../groq/__pycache__/_streaming.cpython-312.pyc    |    Bin [31m16838[m -> [32m0[m bytes
 .../groq/__pycache__/_types.cpython-312.pyc        |    Bin [31m8302[m -> [32m0[m bytes
 .../groq/__pycache__/_version.cpython-312.pyc      |    Bin [31m220[m -> [32m0[m bytes
 .../venv/Lib/site-packages/groq/_base_client.py    |   2001 [31m-[m
 backend/venv/Lib/site-packages/groq/_client.py     |    627 [31m-[m
 backend/venv/Lib/site-packages/groq/_compat.py     |    219 [31m-[m
 backend/venv/Lib/site-packages/groq/_constants.py  |     14 [31m-[m
 backend/venv/Lib/site-packages/groq/_exceptions.py |    108 [31m-[m
 backend/venv/Lib/site-packages/groq/_files.py      |    123 [31m-[m
 backend/venv/Lib/site-packages/groq/_models.py     |    857 [31m-[m
 backend/venv/Lib/site-packages/groq/_qs.py         |    150 [31m-[m
 backend/venv/Lib/site-packages/groq/_resource.py   |     43 [31m-[m
 backend/venv/Lib/site-packages/groq/_response.py   |    830 [31m-[m
 backend/venv/Lib/site-packages/groq/_streaming.py  |    408 [31m-[m
 backend/venv/Lib/site-packages/groq/_types.py      |    261 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/__init__.py |     64 [31m-[m
 .../_utils/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1851[m -> [32m0[m bytes
 .../_utils/__pycache__/_compat.cpython-312.pyc     |    Bin [31m2145[m -> [32m0[m bytes
 .../__pycache__/_datetime_parse.cpython-312.pyc    |    Bin [31m5786[m -> [32m0[m bytes
 .../groq/_utils/__pycache__/_logs.cpython-312.pyc  |    Bin [31m1491[m -> [32m0[m bytes
 .../groq/_utils/__pycache__/_proxy.cpython-312.pyc |    Bin [31m3332[m -> [32m0[m bytes
 .../_utils/__pycache__/_reflection.cpython-312.pyc |    Bin [31m2162[m -> [32m0[m bytes
 .../__pycache__/_resources_proxy.cpython-312.pyc   |    Bin [31m1160[m -> [32m0[m bytes
 .../_utils/__pycache__/_streams.cpython-312.pyc    |    Bin [31m728[m -> [32m0[m bytes
 .../groq/_utils/__pycache__/_sync.cpython-312.pyc  |    Bin [31m2362[m -> [32m0[m bytes
 .../_utils/__pycache__/_transform.cpython-312.pyc  |    Bin [31m15216[m -> [32m0[m bytes
 .../_utils/__pycache__/_typing.cpython-312.pyc     |    Bin [31m5546[m -> [32m0[m bytes
 .../groq/_utils/__pycache__/_utils.cpython-312.pyc |    Bin [31m16583[m -> [32m0[m bytes
 .../venv/Lib/site-packages/groq/_utils/_compat.py  |     45 [31m-[m
 .../site-packages/groq/_utils/_datetime_parse.py   |    136 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_logs.py    |     25 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_proxy.py   |     65 [31m-[m
 .../Lib/site-packages/groq/_utils/_reflection.py   |     42 [31m-[m
 .../site-packages/groq/_utils/_resources_proxy.py  |     24 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_streams.py |     12 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_sync.py    |     58 [31m-[m
 .../Lib/site-packages/groq/_utils/_transform.py    |    457 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_typing.py  |    156 [31m-[m
 .../venv/Lib/site-packages/groq/_utils/_utils.py   |    421 [31m-[m
 backend/venv/Lib/site-packages/groq/_version.py    |      4 [31m-[m
 backend/venv/Lib/site-packages/groq/lib/.keep      |      4 [31m-[m
 backend/venv/Lib/site-packages/groq/py.typed       |      0
 .../Lib/site-packages/groq/resources/__init__.py   |     89 [31m-[m
 .../resources/__pycache__/__init__.cpython-312.pyc |    Bin [31m1693[m -> [32m0[m bytes
 .../resources/__pycache__/batches.cpython-312.pyc  |    Bin [31m11999[m -> [32m0[m bytes
 .../__pycache__/embeddings.cpython-312.pyc         |    Bin [31m7166[m -> [32m0[m bytes
 .../resources/__pycache__/files.cpython-312.pyc    |    Bin [31m14210[m -> [32m0[m bytes
 .../resources/__pycache__/models.cpython-312.pyc   |    Bin [31m8580[m -> [32m0[m bytes
 .../site-packages/groq/resources/audio/__init__.py |     61 [31m-[m
 .../audio/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1289[m -> [32m0[m bytes
 .../audio/__pycache__/audio.cpython-312.pyc        |    Bin [31m8461[m -> [32m0[m bytes
 .../audio/__pycache__/speech.cpython-312.pyc       |    Bin [31m7486[m -> [32m0[m bytes
 .../__pycache__/transcriptions.cpython-312.pyc     |    Bin [31m10405[m -> [32m0[m bytes
 .../audio/__pycache__/translations.cpython-312.pyc |    Bin [31m8617[m -> [32m0[m bytes
 .../site-packages/groq/resources/audio/audio.py    |    166 [31m-[m
 .../site-packages/groq/resources/audio/speech.py   |    233 [31m-[m
 .../groq/resources/audio/transcriptions.py         |    494 [31m-[m
 .../groq/resources/audio/translations.py           |    254 [31m-[m
 .../Lib/site-packages/groq/resources/batches.py    |    429 [31m-[m
 .../site-packages/groq/resources/chat/__init__.py  |     33 [31m-[m
 .../chat/__pycache__/__init__.cpython-312.pyc      |    Bin [31m724[m -> [32m0[m bytes
 .../chat/__pycache__/chat.cpython-312.pyc          |    Bin [31m4994[m -> [32m0[m bytes
 .../chat/__pycache__/completions.cpython-312.pyc   |    Bin [31m29923[m -> [32m0[m bytes
 .../Lib/site-packages/groq/resources/chat/chat.py  |    102 [31m-[m
 .../groq/resources/chat/completions.py             |   1025 [31m-[m
 .../Lib/site-packages/groq/resources/embeddings.py |    212 [31m-[m
 .../venv/Lib/site-packages/groq/resources/files.py |    513 [31m-[m
 .../Lib/site-packages/groq/resources/models.py     |    293 [31m-[m
 .../venv/Lib/site-packages/groq/types/__init__.py  |     26 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1366[m -> [32m0[m bytes
 .../batch_cancel_response.cpython-312.pyc          |    Bin [31m2748[m -> [32m0[m bytes
 .../batch_create_params.cpython-312.pyc            |    Bin [31m854[m -> [32m0[m bytes
 .../batch_create_response.cpython-312.pyc          |    Bin [31m2748[m -> [32m0[m bytes
 .../batch_list_response.cpython-312.pyc            |    Bin [31m3002[m -> [32m0[m bytes
 .../batch_retrieve_response.cpython-312.pyc        |    Bin [31m2752[m -> [32m0[m bytes
 .../__pycache__/completion_usage.cpython-312.pyc   |    Bin [31m1584[m -> [32m0[m bytes
 .../create_embedding_response.cpython-312.pyc      |    Bin [31m1056[m -> [32m0[m bytes
 .../types/__pycache__/embedding.cpython-312.pyc    |    Bin [31m785[m -> [32m0[m bytes
 .../embedding_create_params.cpython-312.pyc        |    Bin [31m950[m -> [32m0[m bytes
 .../__pycache__/file_create_params.cpython-312.pyc |    Bin [31m717[m -> [32m0[m bytes
 .../file_create_response.cpython-312.pyc           |    Bin [31m1019[m -> [32m0[m bytes
 .../file_delete_response.cpython-312.pyc           |    Bin [31m610[m -> [32m0[m bytes
 .../__pycache__/file_info_response.cpython-312.pyc |    Bin [31m1015[m -> [32m0[m bytes
 .../__pycache__/file_list_response.cpython-312.pyc |    Bin [31m1274[m -> [32m0[m bytes
 .../groq/types/__pycache__/model.cpython-312.pyc   |    Bin [31m708[m -> [32m0[m bytes
 .../__pycache__/model_deleted.cpython-312.pyc      |    Bin [31m520[m -> [32m0[m bytes
 .../model_list_response.cpython-312.pyc            |    Bin [31m673[m -> [32m0[m bytes
 .../Lib/site-packages/groq/types/audio/__init__.py |      9 [31m-[m
 .../audio/__pycache__/__init__.cpython-312.pyc     |    Bin [31m550[m -> [32m0[m bytes
 .../speech_create_params.cpython-312.pyc           |    Bin [31m995[m -> [32m0[m bytes
 .../__pycache__/transcription.cpython-312.pyc      |    Bin [31m594[m -> [32m0[m bytes
 .../transcription_create_params.cpython-312.pyc    |    Bin [31m1773[m -> [32m0[m bytes
 .../audio/__pycache__/translation.cpython-312.pyc  |    Bin [31m471[m -> [32m0[m bytes
 .../translation_create_params.cpython-312.pyc      |    Bin [31m1002[m -> [32m0[m bytes
 .../groq/types/audio/speech_create_params.py       |     34 [31m-[m
 .../groq/types/audio/transcription.py              |     14 [31m-[m
 .../types/audio/transcription_create_params.py     |    175 [31m-[m
 .../site-packages/groq/types/audio/translation.py  |      9 [31m-[m
 .../groq/types/audio/translation_create_params.py  |     53 [31m-[m
 .../groq/types/batch_cancel_response.py            |    109 [31m-[m
 .../groq/types/batch_create_params.py              |     34 [31m-[m
 .../groq/types/batch_create_response.py            |    109 [31m-[m
 .../groq/types/batch_list_response.py              |    115 [31m-[m
 .../groq/types/batch_retrieve_response.py          |    109 [31m-[m
 .../Lib/site-packages/groq/types/chat/__init__.py  |     41 [31m-[m
 .../chat/__pycache__/__init__.cpython-312.pyc      |    Bin [31m2067[m -> [32m0[m bytes
 .../__pycache__/chat_completion.cpython-312.pyc    |    Bin [31m5157[m -> [32m0[m bytes
 ...pletion_assistant_message_param.cpython-312.pyc |    Bin [31m1654[m -> [32m0[m bytes
 .../chat_completion_chunk.cpython-312.pyc          |    Bin [31m4917[m -> [32m0[m bytes
 ...letion_content_part_image_param.cpython-312.pyc |    Bin [31m968[m -> [32m0[m bytes
 ...t_completion_content_part_param.cpython-312.pyc |    Bin [31m1482[m -> [32m0[m bytes
 ...pletion_content_part_text_param.cpython-312.pyc |    Bin [31m703[m -> [32m0[m bytes
 ...tion_function_call_option_param.cpython-312.pyc |    Bin [31m768[m -> [32m0[m bytes
 ...mpletion_function_message_param.cpython-312.pyc |    Bin [31m803[m -> [32m0[m bytes
 .../chat_completion_message.cpython-312.pyc        |    Bin [31m6755[m -> [32m0[m bytes
 .../chat_completion_message_param.cpython-312.pyc  |    Bin [31m963[m -> [32m0[m bytes
 ...at_completion_message_tool_call.cpython-312.pyc |    Bin [31m929[m -> [32m0[m bytes
 ...pletion_message_tool_call_param.cpython-312.pyc |    Bin [31m1047[m -> [32m0[m bytes
 ...pletion_named_tool_choice_param.cpython-312.pyc |    Bin [31m1045[m -> [32m0[m bytes
 .../chat_completion_role.cpython-312.pyc           |    Bin [31m413[m -> [32m0[m bytes
 ...completion_system_message_param.cpython-312.pyc |    Bin [31m962[m -> [32m0[m bytes
 .../chat_completion_token_logprob.cpython-312.pyc  |    Bin [31m1047[m -> [32m0[m bytes
 ...letion_tool_choice_option_param.cpython-312.pyc |    Bin [31m647[m -> [32m0[m bytes
 ...t_completion_tool_message_param.cpython-312.pyc |    Bin [31m947[m -> [32m0[m bytes
 .../chat_completion_tool_param.cpython-312.pyc     |    Bin [31m847[m -> [32m0[m bytes
 ...t_completion_user_message_param.cpython-312.pyc |    Bin [31m930[m -> [32m0[m bytes
 .../completion_create_params.cpython-312.pyc       |    Bin [31m8433[m -> [32m0[m bytes
 .../groq/types/chat/chat_completion.py             |    197 [31m-[m
 .../chat_completion_assistant_message_param.py     |     64 [31m-[m
 .../groq/types/chat/chat_completion_chunk.py       |    224 [31m-[m
 .../chat_completion_content_part_image_param.py    |     22 [31m-[m
 .../chat/chat_completion_content_part_param.py     |     37 [31m-[m
 .../chat_completion_content_part_text_param.py     |     15 [31m-[m
 .../chat_completion_function_call_option_param.py  |     16 [31m-[m
 .../chat/chat_completion_function_message_param.py |     19 [31m-[m
 .../groq/types/chat/chat_completion_message.py     |    277 [31m-[m
 .../types/chat/chat_completion_message_param.py    |     22 [31m-[m
 .../chat/chat_completion_message_tool_call.py      |     33 [31m-[m
 .../chat_completion_message_tool_call_param.py     |     33 [31m-[m
 .../chat_completion_named_tool_choice_param.py     |     24 [31m-[m
 .../groq/types/chat/chat_completion_role.py        |      7 [31m-[m
 .../chat/chat_completion_system_message_param.py   |     25 [31m-[m
 .../types/chat/chat_completion_token_logprob.py    |     57 [31m-[m
 .../chat_completion_tool_choice_option_param.py    |     14 [31m-[m
 .../chat/chat_completion_tool_message_param.py     |     21 [31m-[m
 .../groq/types/chat/chat_completion_tool_param.py  |     20 [31m-[m
 .../chat/chat_completion_user_message_param.py     |     25 [31m-[m
 .../groq/types/chat/completion_create_params.py    |    472 [31m-[m
 .../site-packages/groq/types/completion_usage.py   |     52 [31m-[m
 .../groq/types/create_embedding_response.py        |     33 [31m-[m
 .../venv/Lib/site-packages/groq/types/embedding.py |     25 [31m-[m
 .../groq/types/embedding_create_params.py          |     32 [31m-[m
 .../site-packages/groq/types/file_create_params.py |     20 [31m-[m
 .../groq/types/file_create_response.py             |     33 [31m-[m
 .../groq/types/file_delete_response.py             |     15 [31m-[m
 .../site-packages/groq/types/file_info_response.py |     33 [31m-[m
 .../site-packages/groq/types/file_list_response.py |     39 [31m-[m
 backend/venv/Lib/site-packages/groq/types/model.py |     23 [31m-[m
 .../Lib/site-packages/groq/types/model_deleted.py  |     13 [31m-[m
 .../groq/types/model_list_response.py              |     15 [31m-[m
 .../site-packages/groq/types/shared/__init__.py    |      5 [31m-[m
 .../shared/__pycache__/__init__.cpython-312.pyc    |    Bin [31m358[m -> [32m0[m bytes
 .../__pycache__/error_object.cpython-312.pyc       |    Bin [31m1620[m -> [32m0[m bytes
 .../function_definition.cpython-312.pyc            |    Bin [31m801[m -> [32m0[m bytes
 .../function_parameters.cpython-312.pyc            |    Bin [31m406[m -> [32m0[m bytes
 .../groq/types/shared/error_object.py              |     53 [31m-[m
 .../groq/types/shared/function_definition.py       |     38 [31m-[m
 .../groq/types/shared/function_parameters.py       |      8 [31m-[m
 .../groq/types/shared_params/__init__.py           |      4 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m317[m -> [32m0[m bytes
 .../function_definition.cpython-312.pyc            |    Bin [31m794[m -> [32m0[m bytes
 .../function_parameters.cpython-312.pyc            |    Bin [31m465[m -> [32m0[m bytes
 .../types/shared_params/function_definition.py     |     39 [31m-[m
 .../types/shared_params/function_parameters.py     |     10 [31m-[m
 backend/venv/Lib/site-packages/grpc/__init__.py    |   2347 [31m-[m
 .../grpc/__pycache__/__init__.cpython-312.pyc      |    Bin [31m91344[m -> [32m0[m bytes
 .../grpc/__pycache__/_auth.cpython-312.pyc         |    Bin [31m3156[m -> [32m0[m bytes
 .../grpc/__pycache__/_channel.cpython-312.pyc      |    Bin [31m98071[m -> [32m0[m bytes
 .../grpc/__pycache__/_common.cpython-312.pyc       |    Bin [31m9164[m -> [32m0[m bytes
 .../grpc/__pycache__/_compression.cpython-312.pyc  |    Bin [31m1951[m -> [32m0[m bytes
 .../__pycache__/_grpcio_metadata.cpython-312.pyc   |    Bin [31m201[m -> [32m0[m bytes
 .../grpc/__pycache__/_interceptor.cpython-312.pyc  |    Bin [31m30739[m -> [32m0[m bytes
 .../__pycache__/_observability.cpython-312.pyc     |    Bin [31m12792[m -> [32m0[m bytes
 .../__pycache__/_plugin_wrapping.cpython-312.pyc   |    Bin [31m5648[m -> [32m0[m bytes
 .../__pycache__/_runtime_protos.cpython-312.pyc    |    Bin [31m6020[m -> [32m0[m bytes
 .../grpc/__pycache__/_server.cpython-312.pyc       |    Bin [31m63388[m -> [32m0[m bytes
 .../grpc/__pycache__/_simple_stubs.cpython-312.pyc |    Bin [31m25210[m -> [32m0[m bytes
 .../grpc/__pycache__/_typing.cpython-312.pyc       |    Bin [31m2255[m -> [32m0[m bytes
 .../grpc/__pycache__/_utilities.cpython-312.pyc    |    Bin [31m10459[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/grpc/_auth.py       |     80 [31m-[m
 backend/venv/Lib/site-packages/grpc/_channel.py    |   2240 [31m-[m
 backend/venv/Lib/site-packages/grpc/_common.py     |    181 [31m-[m
 .../venv/Lib/site-packages/grpc/_compression.py    |     71 [31m-[m
 .../Lib/site-packages/grpc/_cython/__init__.py     |     13 [31m-[m
 .../_cython/__pycache__/__init__.cpython-312.pyc   |    Bin [31m174[m -> [32m0[m bytes
 .../grpc/_cython/_credentials/roots.pem            |   4337 [31m-[m
 .../site-packages/grpc/_cython/_cygrpc/__init__.py |     13 [31m-[m
 .../_cygrpc/__pycache__/__init__.cpython-312.pyc   |    Bin [31m182[m -> [32m0[m bytes
 .../grpc/_cython/cygrpc.cp312-win_amd64.pyd        |    Bin [31m10348544[m -> [32m0[m bytes
 .../Lib/site-packages/grpc/_grpcio_metadata.py     |      1 [31m-[m
 .../venv/Lib/site-packages/grpc/_interceptor.py    |    809 [31m-[m
 .../venv/Lib/site-packages/grpc/_observability.py  |    312 [31m-[m
 .../Lib/site-packages/grpc/_plugin_wrapping.py     |    137 [31m-[m
 .../venv/Lib/site-packages/grpc/_runtime_protos.py |    164 [31m-[m
 backend/venv/Lib/site-packages/grpc/_server.py     |   1516 [31m-[m
 .../venv/Lib/site-packages/grpc/_simple_stubs.py   |    588 [31m-[m
 backend/venv/Lib/site-packages/grpc/_typing.py     |     96 [31m-[m
 backend/venv/Lib/site-packages/grpc/_utilities.py  |    220 [31m-[m
 .../venv/Lib/site-packages/grpc/aio/__init__.py    |     95 [31m-[m
 .../grpc/aio/__pycache__/__init__.cpython-312.pyc  |    Bin [31m2143[m -> [32m0[m bytes
 .../aio/__pycache__/_base_call.cpython-312.pyc     |    Bin [31m8928[m -> [32m0[m bytes
 .../aio/__pycache__/_base_channel.cpython-312.pyc  |    Bin [31m15940[m -> [32m0[m bytes
 .../aio/__pycache__/_base_server.cpython-312.pyc   |    Bin [31m15890[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_call.cpython-312.pyc     |    Bin [31m35488[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_channel.cpython-312.pyc  |    Bin [31m21824[m -> [32m0[m bytes
 .../aio/__pycache__/_interceptor.cpython-312.pyc   |    Bin [31m47571[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_metadata.cpython-312.pyc |    Bin [31m7513[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_server.cpython-312.pyc   |    Bin [31m10291[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_typing.cpython-312.pyc   |    Bin [31m1145[m -> [32m0[m bytes
 .../grpc/aio/__pycache__/_utils.cpython-312.pyc    |    Bin [31m554[m -> [32m0[m bytes
 .../venv/Lib/site-packages/grpc/aio/_base_call.py  |    257 [31m-[m
 .../Lib/site-packages/grpc/aio/_base_channel.py    |    364 [31m-[m
 .../Lib/site-packages/grpc/aio/_base_server.py     |    387 [31m-[m
 backend/venv/Lib/site-packages/grpc/aio/_call.py   |    758 [31m-[m
 .../venv/Lib/site-packages/grpc/aio/_channel.py    |    628 [31m-[m
 .../Lib/site-packages/grpc/aio/_interceptor.py     |   1177 [31m-[m
 .../venv/Lib/site-packages/grpc/aio/_metadata.py   |    138 [31m-[m
 backend/venv/Lib/site-packages/grpc/aio/_server.py |    240 [31m-[m
 backend/venv/Lib/site-packages/grpc/aio/_typing.py |     43 [31m-[m
 backend/venv/Lib/site-packages/grpc/aio/_utils.py  |     22 [31m-[m
 .../venv/Lib/site-packages/grpc/beta/__init__.py   |     13 [31m-[m
 .../grpc/beta/__pycache__/__init__.cpython-312.pyc |    Bin [31m171[m -> [32m0[m bytes
 .../_client_adaptations.cpython-312.pyc            |    Bin [31m28275[m -> [32m0[m bytes
 .../beta/__pycache__/_metadata.cpython-312.pyc     |    Bin [31m1982[m -> [32m0[m bytes
 .../_server_adaptations.cpython-312.pyc            |    Bin [31m18888[m -> [32m0[m bytes
 .../__pycache__/implementations.cpython-312.pyc    |    Bin [31m12155[m -> [32m0[m bytes
 .../beta/__pycache__/interfaces.cpython-312.pyc    |    Bin [31m7277[m -> [32m0[m bytes
 .../beta/__pycache__/utilities.cpython-312.pyc     |    Bin [31m6991[m -> [32m0[m bytes
 .../site-packages/grpc/beta/_client_adaptations.py |   1010 [31m-[m
 .../venv/Lib/site-packages/grpc/beta/_metadata.py  |     54 [31m-[m
 .../site-packages/grpc/beta/_server_adaptations.py |    459 [31m-[m
 .../Lib/site-packages/grpc/beta/implementations.py |    345 [31m-[m
 .../venv/Lib/site-packages/grpc/beta/interfaces.py |    163 [31m-[m
 .../venv/Lib/site-packages/grpc/beta/utilities.py  |    149 [31m-[m
 .../site-packages/grpc/experimental/__init__.py    |    134 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m4411[m -> [32m0[m bytes
 .../__pycache__/gevent.cpython-312.pyc             |    Bin [31m716[m -> [32m0[m bytes
 .../__pycache__/session_cache.cpython-312.pyc      |    Bin [31m1674[m -> [32m0[m bytes
 .../grpc/experimental/aio/__init__.py              |     16 [31m-[m
 .../aio/__pycache__/__init__.cpython-312.pyc       |    Bin [31m282[m -> [32m0[m bytes
 .../Lib/site-packages/grpc/experimental/gevent.py  |     27 [31m-[m
 .../grpc/experimental/session_cache.py             |     45 [31m-[m
 .../Lib/site-packages/grpc/framework/__init__.py   |     13 [31m-[m
 .../framework/__pycache__/__init__.cpython-312.pyc |    Bin [31m176[m -> [32m0[m bytes
 .../grpc/framework/common/__init__.py              |     13 [31m-[m
 .../common/__pycache__/__init__.cpython-312.pyc    |    Bin [31m183[m -> [32m0[m bytes
 .../common/__pycache__/cardinality.cpython-312.pyc |    Bin [31m850[m -> [32m0[m bytes
 .../common/__pycache__/style.cpython-312.pyc       |    Bin [31m674[m -> [32m0[m bytes
 .../grpc/framework/common/cardinality.py           |     26 [31m-[m
 .../site-packages/grpc/framework/common/style.py   |     24 [31m-[m
 .../grpc/framework/foundation/__init__.py          |     13 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m187[m -> [32m0[m bytes
 .../__pycache__/abandonment.cpython-312.pyc        |    Bin [31m662[m -> [32m0[m bytes
 .../__pycache__/callable_util.cpython-312.pyc      |    Bin [31m3928[m -> [32m0[m bytes
 .../foundation/__pycache__/future.cpython-312.pyc  |    Bin [31m7955[m -> [32m0[m bytes
 .../__pycache__/logging_pool.cpython-312.pyc       |    Bin [31m3129[m -> [32m0[m bytes
 .../foundation/__pycache__/stream.cpython-312.pyc  |    Bin [31m1508[m -> [32m0[m bytes
 .../__pycache__/stream_util.cpython-312.pyc        |    Bin [31m7615[m -> [32m0[m bytes
 .../grpc/framework/foundation/abandonment.py       |     22 [31m-[m
 .../grpc/framework/foundation/callable_util.py     |     98 [31m-[m
 .../grpc/framework/foundation/future.py            |    219 [31m-[m
 .../grpc/framework/foundation/logging_pool.py      |     72 [31m-[m
 .../grpc/framework/foundation/stream.py            |     43 [31m-[m
 .../grpc/framework/foundation/stream_util.py       |    147 [31m-[m
 .../grpc/framework/interfaces/__init__.py          |     13 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m187[m -> [32m0[m bytes
 .../grpc/framework/interfaces/base/__init__.py     |     13 [31m-[m
 .../base/__pycache__/__init__.cpython-312.pyc      |    Bin [31m192[m -> [32m0[m bytes
 .../base/__pycache__/base.cpython-312.pyc          |    Bin [31m14870[m -> [32m0[m bytes
 .../base/__pycache__/utilities.cpython-312.pyc     |    Bin [31m2393[m -> [32m0[m bytes
 .../grpc/framework/interfaces/base/base.py         |    328 [31m-[m
 .../grpc/framework/interfaces/base/utilities.py    |     83 [31m-[m
 .../grpc/framework/interfaces/face/__init__.py     |     13 [31m-[m
 .../face/__pycache__/__init__.cpython-312.pyc      |    Bin [31m192[m -> [32m0[m bytes
 .../face/__pycache__/face.cpython-312.pyc          |    Bin [31m44182[m -> [32m0[m bytes
 .../face/__pycache__/utilities.cpython-312.pyc     |    Bin [31m6853[m -> [32m0[m bytes
 .../grpc/framework/interfaces/face/face.py         |   1084 [31m-[m
 .../grpc/framework/interfaces/face/utilities.py    |    245 [31m-[m
 .../venv/Lib/site-packages/grpc_status/__init__.py |     13 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m173[m -> [32m0[m bytes
 .../grpc_status/__pycache__/_async.cpython-312.pyc |    Bin [31m1940[m -> [32m0[m bytes
 .../__pycache__/_common.cpython-312.pyc            |    Bin [31m817[m -> [32m0[m bytes
 .../__pycache__/rpc_status.cpython-312.pyc         |    Bin [31m3230[m -> [32m0[m bytes
 .../venv/Lib/site-packages/grpc_status/_async.py   |     58 [31m-[m
 .../venv/Lib/site-packages/grpc_status/_common.py  |     27 [31m-[m
 .../Lib/site-packages/grpc_status/rpc_status.py    |     96 [31m-[m
 .../grpcio-1.76.0.dist-info/INSTALLER              |      1 [31m-[m
 .../site-packages/grpcio-1.76.0.dist-info/LICENSE  |    610 [31m-[m
 .../site-packages/grpcio-1.76.0.dist-info/METADATA |    126 [31m-[m
 .../site-packages/grpcio-1.76.0.dist-info/RECORD   |    120 [31m-[m
 .../site-packages/grpcio-1.76.0.dist-info/WHEEL    |      5 [31m-[m
 .../grpcio-1.76.0.dist-info/top_level.txt          |      1 [31m-[m
 .../grpcio_status-1.71.2.dist-info/INSTALLER       |      1 [31m-[m
 .../grpcio_status-1.71.2.dist-info/LICENSE         |    610 [31m-[m
 .../grpcio_status-1.71.2.dist-info/METADATA        |     33 [31m-[m
 .../grpcio_status-1.71.2.dist-info/RECORD          |     14 [31m-[m
 .../grpcio_status-1.71.2.dist-info/WHEEL           |      5 [31m-[m
 .../grpcio_status-1.71.2.dist-info/top_level.txt   |      1 [31m-[m
 .../site-packages/h11-0.16.0.dist-info/INSTALLER   |      1 [31m-[m
 .../site-packages/h11-0.16.0.dist-info/METADATA    |    202 [31m-[m
 .../Lib/site-packages/h11-0.16.0.dist-info/RECORD  |     29 [31m-[m
 .../Lib/site-packages/h11-0.16.0.dist-info/WHEEL   |      5 [31m-[m
 .../h11-0.16.0.dist-info/licenses/LICENSE.txt      |     22 [31m-[m
 .../h11-0.16.0.dist-info/top_level.txt             |      1 [31m-[m
 backend/venv/Lib/site-packages/h11/__init__.py     |     62 [31m-[m
 .../h11/__pycache__/__init__.cpython-312.pyc       |    Bin [31m1056[m -> [32m0[m bytes
 .../h11/__pycache__/_abnf.cpython-312.pyc          |    Bin [31m1762[m -> [32m0[m bytes
 .../h11/__pycache__/_connection.cpython-312.pyc    |    Bin [31m23112[m -> [32m0[m bytes
 .../h11/__pycache__/_events.cpython-312.pyc        |    Bin [31m13202[m -> [32m0[m bytes
 .../h11/__pycache__/_headers.cpython-312.pyc       |    Bin [31m7964[m -> [32m0[m bytes
 .../h11/__pycache__/_readers.cpython-312.pyc       |    Bin [31m9629[m -> [32m0[m bytes
 .../h11/__pycache__/_receivebuffer.cpython-312.pyc |    Bin [31m4680[m -> [32m0[m bytes
 .../h11/__pycache__/_state.cpython-312.pyc         |    Bin [31m8444[m -> [32m0[m bytes
 .../h11/__pycache__/_util.cpython-312.pyc          |    Bin [31m4700[m -> [32m0[m bytes
 .../h11/__pycache__/_version.cpython-312.pyc       |    Bin [31m194[m -> [32m0[m bytes
 .../h11/__pycache__/_writers.cpython-312.pyc       |    Bin [31m6266[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/h11/_abnf.py        |    132 [31m-[m
 backend/venv/Lib/site-packages/h11/_connection.py  |    659 [31m-[m
 backend/venv/Lib/site-packages/h11/_events.py      |    369 [31m-[m
 backend/venv/Lib/site-packages/h11/_headers.py     |    282 [31m-[m
 backend/venv/Lib/site-packages/h11/_readers.py     |    250 [31m-[m
 .../venv/Lib/site-packages/h11/_receivebuffer.py   |    153 [31m-[m
 backend/venv/Lib/site-packages/h11/_state.py       |    365 [31m-[m
 backend/venv/Lib/site-packages/h11/_util.py        |    135 [31m-[m
 backend/venv/Lib/site-packages/h11/_version.py     |     16 [31m-[m
 backend/venv/Lib/site-packages/h11/_writers.py     |    145 [31m-[m
 backend/venv/Lib/site-packages/h11/py.typed        |      1 [31m-[m
 .../site-packages/hf_xet-1.2.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/hf_xet-1.2.0.dist-info/METADATA  |     87 [31m-[m
 .../site-packages/hf_xet-1.2.0.dist-info/RECORD    |      8 [31m-[m
 .../Lib/site-packages/hf_xet-1.2.0.dist-info/WHEEL |      4 [31m-[m
 .../hf_xet-1.2.0.dist-info/licenses/LICENSE        |    201 [31m-[m
 backend/venv/Lib/site-packages/hf_xet/__init__.py  |      5 [31m-[m
 .../hf_xet/__pycache__/__init__.cpython-312.pyc    |    Bin [31m329[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/hf_xet/hf_xet.pyd   |    Bin [31m7011840[m -> [32m0[m bytes
 .../httpcore-1.0.9.dist-info/INSTALLER             |      1 [31m-[m
 .../httpcore-1.0.9.dist-info/METADATA              |    625 [31m-[m
 .../site-packages/httpcore-1.0.9.dist-info/RECORD  |     68 [31m-[m
 .../site-packages/httpcore-1.0.9.dist-info/WHEEL   |      4 [31m-[m
 .../httpcore-1.0.9.dist-info/licenses/LICENSE.md   |     27 [31m-[m
 .../venv/Lib/site-packages/httpcore/__init__.py    |    141 [31m-[m
 .../httpcore/__pycache__/__init__.cpython-312.pyc  |    Bin [31m3147[m -> [32m0[m bytes
 .../httpcore/__pycache__/_api.cpython-312.pyc      |    Bin [31m3733[m -> [32m0[m bytes
 .../__pycache__/_exceptions.cpython-312.pyc        |    Bin [31m3166[m -> [32m0[m bytes
 .../httpcore/__pycache__/_models.cpython-312.pyc   |    Bin [31m23113[m -> [32m0[m bytes
 .../httpcore/__pycache__/_ssl.cpython-312.pyc      |    Bin [31m591[m -> [32m0[m bytes
 .../__pycache__/_synchronization.cpython-312.pyc   |    Bin [31m14134[m -> [32m0[m bytes
 .../httpcore/__pycache__/_trace.cpython-312.pyc    |    Bin [31m5591[m -> [32m0[m bytes
 .../httpcore/__pycache__/_utils.cpython-312.pyc    |    Bin [31m1271[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/httpcore/_api.py    |     94 [31m-[m
 .../Lib/site-packages/httpcore/_async/__init__.py  |     39 [31m-[m
 .../_async/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1604[m -> [32m0[m bytes
 .../_async/__pycache__/connection.cpython-312.pyc  |    Bin [31m11697[m -> [32m0[m bytes
 .../__pycache__/connection_pool.cpython-312.pyc    |    Bin [31m19579[m -> [32m0[m bytes
 .../_async/__pycache__/http11.cpython-312.pyc      |    Bin [31m20090[m -> [32m0[m bytes
 .../_async/__pycache__/http2.cpython-312.pyc       |    Bin [31m31156[m -> [32m0[m bytes
 .../_async/__pycache__/http_proxy.cpython-312.pyc  |    Bin [31m17951[m -> [32m0[m bytes
 .../_async/__pycache__/interfaces.cpython-312.pyc  |    Bin [31m5735[m -> [32m0[m bytes
 .../_async/__pycache__/socks_proxy.cpython-312.pyc |    Bin [31m16825[m -> [32m0[m bytes
 .../site-packages/httpcore/_async/connection.py    |    222 [31m-[m
 .../httpcore/_async/connection_pool.py             |    420 [31m-[m
 .../Lib/site-packages/httpcore/_async/http11.py    |    379 [31m-[m
 .../Lib/site-packages/httpcore/_async/http2.py     |    592 [31m-[m
 .../site-packages/httpcore/_async/http_proxy.py    |    367 [31m-[m
 .../site-packages/httpcore/_async/interfaces.py    |    137 [31m-[m
 .../site-packages/httpcore/_async/socks_proxy.py   |    341 [31m-[m
 .../site-packages/httpcore/_backends/__init__.py   |      0
 .../_backends/__pycache__/__init__.cpython-312.pyc |    Bin [31m180[m -> [32m0[m bytes
 .../_backends/__pycache__/anyio.cpython-312.pyc    |    Bin [31m8524[m -> [32m0[m bytes
 .../_backends/__pycache__/auto.cpython-312.pyc     |    Bin [31m2672[m -> [32m0[m bytes
 .../_backends/__pycache__/base.cpython-312.pyc     |    Bin [31m4874[m -> [32m0[m bytes
 .../_backends/__pycache__/mock.cpython-312.pyc     |    Bin [31m7138[m -> [32m0[m bytes
 .../_backends/__pycache__/sync.cpython-312.pyc     |    Bin [31m11345[m -> [32m0[m bytes
 .../_backends/__pycache__/trio.cpython-312.pyc     |    Bin [31m8863[m -> [32m0[m bytes
 .../Lib/site-packages/httpcore/_backends/anyio.py  |    146 [31m-[m
 .../Lib/site-packages/httpcore/_backends/auto.py   |     52 [31m-[m
 .../Lib/site-packages/httpcore/_backends/base.py   |    101 [31m-[m
 .../Lib/site-packages/httpcore/_backends/mock.py   |    143 [31m-[m
 .../Lib/site-packages/httpcore/_backends/sync.py   |    241 [31m-[m
 .../Lib/site-packages/httpcore/_backends/trio.py   |    159 [31m-[m
 .../venv/Lib/site-packages/httpcore/_exceptions.py |     81 [31m-[m
 backend/venv/Lib/site-packages/httpcore/_models.py |    516 [31m-[m
 backend/venv/Lib/site-packages/httpcore/_ssl.py    |      9 [31m-[m
 .../Lib/site-packages/httpcore/_sync/__init__.py   |     39 [31m-[m
 .../_sync/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1558[m -> [32m0[m bytes
 .../_sync/__pycache__/connection.cpython-312.pyc   |    Bin [31m10354[m -> [32m0[m bytes
 .../__pycache__/connection_pool.cpython-312.pyc    |    Bin [31m18656[m -> [32m0[m bytes
 .../_sync/__pycache__/http11.cpython-312.pyc       |    Bin [31m17677[m -> [32m0[m bytes
 .../_sync/__pycache__/http2.cpython-312.pyc        |    Bin [31m27288[m -> [32m0[m bytes
 .../_sync/__pycache__/http_proxy.cpython-312.pyc   |    Bin [31m17154[m -> [32m0[m bytes
 .../_sync/__pycache__/interfaces.cpython-312.pyc   |    Bin [31m5282[m -> [32m0[m bytes
 .../_sync/__pycache__/socks_proxy.cpython-312.pyc  |    Bin [31m15603[m -> [32m0[m bytes
 .../Lib/site-packages/httpcore/_sync/connection.py |    222 [31m-[m
 .../httpcore/_sync/connection_pool.py              |    420 [31m-[m
 .../Lib/site-packages/httpcore/_sync/http11.py     |    379 [31m-[m
 .../venv/Lib/site-packages/httpcore/_sync/http2.py |    592 [31m-[m
 .../Lib/site-packages/httpcore/_sync/http_proxy.py |    367 [31m-[m
 .../Lib/site-packages/httpcore/_sync/interfaces.py |    137 [31m-[m
 .../site-packages/httpcore/_sync/socks_proxy.py    |    341 [31m-[m
 .../Lib/site-packages/httpcore/_synchronization.py |    318 [31m-[m
 backend/venv/Lib/site-packages/httpcore/_trace.py  |    107 [31m-[m
 backend/venv/Lib/site-packages/httpcore/_utils.py  |     37 [31m-[m
 backend/venv/Lib/site-packages/httpcore/py.typed   |      0
 .../httplib2-0.31.0.dist-info/INSTALLER            |      1 [31m-[m
 .../httplib2-0.31.0.dist-info/METADATA             |     74 [31m-[m
 .../site-packages/httplib2-0.31.0.dist-info/RECORD |     17 [31m-[m
 .../site-packages/httplib2-0.31.0.dist-info/WHEEL  |      5 [31m-[m
 .../httplib2-0.31.0.dist-info/licenses/LICENSE     |     23 [31m-[m
 .../httplib2-0.31.0.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/httplib2/__init__.py    |   1802 [31m-[m
 .../httplib2/__pycache__/__init__.cpython-312.pyc  |    Bin [31m73211[m -> [32m0[m bytes
 .../httplib2/__pycache__/auth.cpython-312.pyc      |    Bin [31m3865[m -> [32m0[m bytes
 .../httplib2/__pycache__/certs.cpython-312.pyc     |    Bin [31m1536[m -> [32m0[m bytes
 .../httplib2/__pycache__/error.cpython-312.pyc     |    Bin [31m2199[m -> [32m0[m bytes
 .../httplib2/__pycache__/iri2uri.cpython-312.pyc   |    Bin [31m4142[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/httplib2/auth.py    |     68 [31m-[m
 .../venv/Lib/site-packages/httplib2/cacerts.txt    |   2225 [31m-[m
 backend/venv/Lib/site-packages/httplib2/certs.py   |     42 [31m-[m
 backend/venv/Lib/site-packages/httplib2/error.py   |     48 [31m-[m
 backend/venv/Lib/site-packages/httplib2/iri2uri.py |    124 [31m-[m
 .../httptools-0.7.1.dist-info/INSTALLER            |      1 [31m-[m
 .../httptools-0.7.1.dist-info/METADATA             |    130 [31m-[m
 .../site-packages/httptools-0.7.1.dist-info/RECORD |     25 [31m-[m
 .../site-packages/httptools-0.7.1.dist-info/WHEEL  |      5 [31m-[m
 .../httptools-0.7.1.dist-info/licenses/LICENSE     |     21 [31m-[m
 .../httptools-0.7.1.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/httptools/__init__.py   |      6 [31m-[m
 .../httptools/__pycache__/__init__.cpython-312.pyc |    Bin [31m322[m -> [32m0[m bytes
 .../httptools/__pycache__/_version.cpython-312.pyc |    Bin [31m199[m -> [32m0[m bytes
 .../venv/Lib/site-packages/httptools/_version.py   |     13 [31m-[m
 .../Lib/site-packages/httptools/parser/__init__.py |      6 [31m-[m
 .../parser/__pycache__/__init__.cpython-312.pyc    |    Bin [31m412[m -> [32m0[m bytes
 .../parser/__pycache__/errors.cpython-312.pyc      |    Bin [31m1196[m -> [32m0[m bytes
 .../parser/__pycache__/protocol.cpython-312.pyc    |    Bin [31m1826[m -> [32m0[m bytes
 .../Lib/site-packages/httptools/parser/cparser.pxd |    167 [31m-[m
 .../Lib/site-packages/httptools/parser/errors.py   |     30 [31m-[m
 .../httptools/parser/parser.cp312-win_amd64.pyd    |    Bin [31m124928[m -> [32m0[m bytes
 .../Lib/site-packages/httptools/parser/parser.pyi  |     57 [31m-[m
 .../Lib/site-packages/httptools/parser/parser.pyx  |    436 [31m-[m
 .../Lib/site-packages/httptools/parser/protocol.py |     15 [31m-[m
 .../Lib/site-packages/httptools/parser/python.pxd  |      6 [31m-[m
 .../site-packages/httptools/parser/url_cparser.pxd |     31 [31m-[m
 .../parser/url_parser.cp312-win_amd64.pyd          |    Bin [31m53248[m -> [32m0[m bytes
 .../site-packages/httptools/parser/url_parser.pyi  |     27 [31m-[m
 .../site-packages/httptools/parser/url_parser.pyx  |    108 [31m-[m
 .../site-packages/httpx-0.28.1.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/httpx-0.28.1.dist-info/METADATA  |    203 [31m-[m
 .../site-packages/httpx-0.28.1.dist-info/RECORD    |     55 [31m-[m
 .../site-packages/httpx-0.28.1.dist-info/REQUESTED |      0
 .../Lib/site-packages/httpx-0.28.1.dist-info/WHEEL |      4 [31m-[m
 .../httpx-0.28.1.dist-info/entry_points.txt        |      2 [31m-[m
 .../httpx-0.28.1.dist-info/licenses/LICENSE.md     |     12 [31m-[m
 backend/venv/Lib/site-packages/httpx/__init__.py   |    105 [31m-[m
 .../httpx/__pycache__/__init__.cpython-312.pyc     |    Bin [31m2101[m -> [32m0[m bytes
 .../httpx/__pycache__/__version__.cpython-312.pyc  |    Bin [31m296[m -> [32m0[m bytes
 .../httpx/__pycache__/_api.cpython-312.pyc         |    Bin [31m10316[m -> [32m0[m bytes
 .../httpx/__pycache__/_auth.cpython-312.pyc        |    Bin [31m15568[m -> [32m0[m bytes
 .../httpx/__pycache__/_client.cpython-312.pyc      |    Bin [31m64112[m -> [32m0[m bytes
 .../httpx/__pycache__/_config.cpython-312.pyc      |    Bin [31m10964[m -> [32m0[m bytes
 .../httpx/__pycache__/_content.cpython-312.pyc     |    Bin [31m10376[m -> [32m0[m bytes
 .../httpx/__pycache__/_decoders.cpython-312.pyc    |    Bin [31m16734[m -> [32m0[m bytes
 .../httpx/__pycache__/_exceptions.cpython-312.pyc  |    Bin [31m12066[m -> [32m0[m bytes
 .../httpx/__pycache__/_main.cpython-312.pyc        |    Bin [31m20571[m -> [32m0[m bytes
 .../httpx/__pycache__/_models.cpython-312.pyc      |    Bin [31m58231[m -> [32m0[m bytes
 .../httpx/__pycache__/_multipart.cpython-312.pyc   |    Bin [31m13550[m -> [32m0[m bytes
 .../__pycache__/_status_codes.cpython-312.pyc      |    Bin [31m7171[m -> [32m0[m bytes
 .../httpx/__pycache__/_types.cpython-312.pyc       |    Bin [31m3808[m -> [32m0[m bytes
 .../httpx/__pycache__/_urlparse.cpython-312.pyc    |    Bin [31m17496[m -> [32m0[m bytes
 .../httpx/__pycache__/_urls.cpython-312.pyc        |    Bin [31m27924[m -> [32m0[m bytes
 .../httpx/__pycache__/_utils.cpython-312.pyc       |    Bin [31m9338[m -> [32m0[m bytes
 .../venv/Lib/site-packages/httpx/__version__.py    |      3 [31m-[m
 backend/venv/Lib/site-packages/httpx/_api.py       |    438 [31m-[m
 backend/venv/Lib/site-packages/httpx/_auth.py      |    348 [31m-[m
 backend/venv/Lib/site-packages/httpx/_client.py    |   2019 [31m-[m
 backend/venv/Lib/site-packages/httpx/_config.py    |    248 [31m-[m
 backend/venv/Lib/site-packages/httpx/_content.py   |    240 [31m-[m
 backend/venv/Lib/site-packages/httpx/_decoders.py  |    393 [31m-[m
 .../venv/Lib/site-packages/httpx/_exceptions.py    |    379 [31m-[m
 backend/venv/Lib/site-packages/httpx/_main.py      |    506 [31m-[m
 backend/venv/Lib/site-packages/httpx/_models.py    |   1277 [31m-[m
 backend/venv/Lib/site-packages/httpx/_multipart.py |    300 [31m-[m
 .../venv/Lib/site-packages/httpx/_status_codes.py  |    162 [31m-[m
 .../site-packages/httpx/_transports/__init__.py    |     15 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m425[m -> [32m0[m bytes
 .../_transports/__pycache__/asgi.cpython-312.pyc   |    Bin [31m7568[m -> [32m0[m bytes
 .../_transports/__pycache__/base.cpython-312.pyc   |    Bin [31m3855[m -> [32m0[m bytes
 .../__pycache__/default.cpython-312.pyc            |    Bin [31m17034[m -> [32m0[m bytes
 .../_transports/__pycache__/mock.cpython-312.pyc   |    Bin [31m1923[m -> [32m0[m bytes
 .../_transports/__pycache__/wsgi.cpython-312.pyc   |    Bin [31m6787[m -> [32m0[m bytes
 .../Lib/site-packages/httpx/_transports/asgi.py    |    187 [31m-[m
 .../Lib/site-packages/httpx/_transports/base.py    |     86 [31m-[m
 .../Lib/site-packages/httpx/_transports/default.py |    406 [31m-[m
 .../Lib/site-packages/httpx/_transports/mock.py    |     43 [31m-[m
 .../Lib/site-packages/httpx/_transports/wsgi.py    |    149 [31m-[m
 backend/venv/Lib/site-packages/httpx/_types.py     |    114 [31m-[m
 backend/venv/Lib/site-packages/httpx/_urlparse.py  |    527 [31m-[m
 backend/venv/Lib/site-packages/httpx/_urls.py      |    641 [31m-[m
 backend/venv/Lib/site-packages/httpx/_utils.py     |    242 [31m-[m
 backend/venv/Lib/site-packages/httpx/py.typed      |      0
 .../huggingface_hub-1.2.3.dist-info/INSTALLER      |      1 [31m-[m
 .../huggingface_hub-1.2.3.dist-info/METADATA       |    320 [31m-[m
 .../huggingface_hub-1.2.3.dist-info/RECORD         |    307 [31m-[m
 .../huggingface_hub-1.2.3.dist-info/REQUESTED      |      0
 .../huggingface_hub-1.2.3.dist-info/WHEEL          |      5 [31m-[m
 .../entry_points.txt                               |      6 [31m-[m
 .../licenses/LICENSE                               |    201 [31m-[m
 .../huggingface_hub-1.2.3.dist-info/top_level.txt  |      1 [31m-[m
 .../Lib/site-packages/huggingface_hub/__init__.py  |   1560 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m22888[m -> [32m0[m bytes
 .../__pycache__/_commit_api.cpython-312.pyc        |    Bin [31m42172[m -> [32m0[m bytes
 .../__pycache__/_commit_scheduler.cpython-312.pyc  |    Bin [31m18497[m -> [32m0[m bytes
 .../_inference_endpoints.cpython-312.pyc           |    Bin [31m20299[m -> [32m0[m bytes
 .../__pycache__/_jobs_api.cpython-312.pyc          |    Bin [31m13839[m -> [32m0[m bytes
 .../__pycache__/_local_folder.cpython-312.pyc      |    Bin [31m20279[m -> [32m0[m bytes
 .../__pycache__/_login.cpython-312.pyc             |    Bin [31m20667[m -> [32m0[m bytes
 .../__pycache__/_oauth.cpython-312.pyc             |    Bin [31m21019[m -> [32m0[m bytes
 .../__pycache__/_snapshot_download.cpython-312.pyc |    Bin [31m19801[m -> [32m0[m bytes
 .../__pycache__/_space_api.cpython-312.pyc         |    Bin [31m6322[m -> [32m0[m bytes
 .../_tensorboard_logger.cpython-312.pyc            |    Bin [31m8565[m -> [32m0[m bytes
 .../_upload_large_folder.cpython-312.pyc           |    Bin [31m36426[m -> [32m0[m bytes
 .../__pycache__/_webhooks_payload.cpython-312.pyc  |    Bin [31m4744[m -> [32m0[m bytes
 .../__pycache__/_webhooks_server.cpython-312.pyc   |    Bin [31m17741[m -> [32m0[m bytes
 .../__pycache__/community.cpython-312.pyc          |    Bin [31m15191[m -> [32m0[m bytes
 .../__pycache__/constants.cpython-312.pyc          |    Bin [31m10684[m -> [32m0[m bytes
 .../__pycache__/dataclasses.cpython-312.pyc        |    Bin [31m24779[m -> [32m0[m bytes
 .../__pycache__/errors.cpython-312.pyc             |    Bin [31m17592[m -> [32m0[m bytes
 .../__pycache__/fastai_utils.cpython-312.pyc       |    Bin [31m17794[m -> [32m0[m bytes
 .../__pycache__/file_download.cpython-312.pyc      |    Bin [31m73934[m -> [32m0[m bytes
 .../__pycache__/hf_api.cpython-312.pyc             |    Bin [31m494355[m -> [32m0[m bytes
 .../__pycache__/hf_file_system.cpython-312.pyc     |    Bin [31m57441[m -> [32m0[m bytes
 .../__pycache__/hub_mixin.cpython-312.pyc          |    Bin [31m37371[m -> [32m0[m bytes
 .../__pycache__/lfs.cpython-312.pyc                |    Bin [31m16719[m -> [32m0[m bytes
 .../__pycache__/repocard.cpython-312.pyc           |    Bin [31m35774[m -> [32m0[m bytes
 .../__pycache__/repocard_data.cpython-312.pyc      |    Bin [31m35863[m -> [32m0[m bytes
 .../site-packages/huggingface_hub/_commit_api.py   |    966 [31m-[m
 .../huggingface_hub/_commit_scheduler.py           |    353 [31m-[m
 .../huggingface_hub/_inference_endpoints.py        |    418 [31m-[m
 .../Lib/site-packages/huggingface_hub/_jobs_api.py |    301 [31m-[m
 .../site-packages/huggingface_hub/_local_folder.py |    451 [31m-[m
 .../Lib/site-packages/huggingface_hub/_login.py    |    492 [31m-[m
 .../Lib/site-packages/huggingface_hub/_oauth.py    |    460 [31m-[m
 .../huggingface_hub/_snapshot_download.py          |    465 [31m-[m
 .../site-packages/huggingface_hub/_space_api.py    |    168 [31m-[m
 .../huggingface_hub/_tensorboard_logger.py         |    190 [31m-[m
 .../huggingface_hub/_upload_large_folder.py        |    741 [31m-[m
 .../huggingface_hub/_webhooks_payload.py           |    137 [31m-[m
 .../huggingface_hub/_webhooks_server.py            |    376 [31m-[m
 .../site-packages/huggingface_hub/cli/__init__.py  |     13 [31m-[m
 .../cli/__pycache__/__init__.cpython-312.pyc       |    Bin [31m181[m -> [32m0[m bytes
 .../cli/__pycache__/_cli_utils.cpython-312.pyc     |    Bin [31m6516[m -> [32m0[m bytes
 .../cli/__pycache__/auth.cpython-312.pyc           |    Bin [31m5793[m -> [32m0[m bytes
 .../cli/__pycache__/cache.cpython-312.pyc          |    Bin [31m35743[m -> [32m0[m bytes
 .../cli/__pycache__/download.cpython-312.pyc       |    Bin [31m7247[m -> [32m0[m bytes
 .../cli/__pycache__/hf.cpython-312.pyc             |    Bin [31m2808[m -> [32m0[m bytes
 .../inference_endpoints.cpython-312.pyc            |    Bin [31m15146[m -> [32m0[m bytes
 .../cli/__pycache__/jobs.cpython-312.pyc           |    Bin [31m28349[m -> [32m0[m bytes
 .../cli/__pycache__/lfs.cpython-312.pyc            |    Bin [31m6239[m -> [32m0[m bytes
 .../cli/__pycache__/repo.cpython-312.pyc           |    Bin [31m13599[m -> [32m0[m bytes
 .../cli/__pycache__/repo_files.cpython-312.pyc     |    Bin [31m2820[m -> [32m0[m bytes
 .../cli/__pycache__/system.cpython-312.pyc         |    Bin [31m764[m -> [32m0[m bytes
 .../cli/__pycache__/upload.cpython-312.pyc         |    Bin [31m10702[m -> [32m0[m bytes
 .../upload_large_folder.cpython-312.pyc            |    Bin [31m4266[m -> [32m0[m bytes
 .../huggingface_hub/cli/_cli_utils.py              |    174 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/auth.py  |    147 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/cache.py |    841 [31m-[m
 .../site-packages/huggingface_hub/cli/download.py  |    189 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/hf.py    |     62 [31m-[m
 .../huggingface_hub/cli/inference_endpoints.py     |    426 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/jobs.py  |    772 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/lfs.py   |    175 [31m-[m
 .../Lib/site-packages/huggingface_hub/cli/repo.py  |    315 [31m-[m
 .../huggingface_hub/cli/repo_files.py              |     94 [31m-[m
 .../site-packages/huggingface_hub/cli/system.py    |     33 [31m-[m
 .../site-packages/huggingface_hub/cli/upload.py    |    294 [31m-[m
 .../huggingface_hub/cli/upload_large_folder.py     |    117 [31m-[m
 .../Lib/site-packages/huggingface_hub/community.py |    363 [31m-[m
 .../Lib/site-packages/huggingface_hub/constants.py |    279 [31m-[m
 .../site-packages/huggingface_hub/dataclasses.py   |    609 [31m-[m
 .../Lib/site-packages/huggingface_hub/errors.py    |    404 [31m-[m
 .../site-packages/huggingface_hub/fastai_utils.py  |    414 [31m-[m
 .../site-packages/huggingface_hub/file_download.py |   1958 [31m-[m
 .../Lib/site-packages/huggingface_hub/hf_api.py    |  11118 [31m--[m
 .../huggingface_hub/hf_file_system.py              |   1275 [31m-[m
 .../Lib/site-packages/huggingface_hub/hub_mixin.py |    831 [31m-[m
 .../huggingface_hub/inference/__init__.py          |      0
 .../inference/__pycache__/__init__.cpython-312.pyc |    Bin [31m187[m -> [32m0[m bytes
 .../inference/__pycache__/_client.cpython-312.pyc  |    Bin [31m152610[m -> [32m0[m bytes
 .../inference/__pycache__/_common.cpython-312.pyc  |    Bin [31m16601[m -> [32m0[m bytes
 .../huggingface_hub/inference/_client.py           |   3385 [31m-[m
 .../huggingface_hub/inference/_common.py           |    434 [31m-[m
 .../inference/_generated/__init__.py               |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m198[m -> [32m0[m bytes
 .../__pycache__/_async_client.cpython-312.pyc      |    Bin [31m158701[m -> [32m0[m bytes
 .../inference/_generated/_async_client.py          |   3440 [31m-[m
 .../inference/_generated/types/__init__.py         |    192 [31m-[m
 .../types/__pycache__/__init__.cpython-312.pyc     |    Bin [31m7780[m -> [32m0[m bytes
 .../audio_classification.cpython-312.pyc           |    Bin [31m1587[m -> [32m0[m bytes
 .../__pycache__/audio_to_audio.cpython-312.pyc     |    Bin [31m1057[m -> [32m0[m bytes
 .../automatic_speech_recognition.cpython-312.pyc   |    Bin [31m3290[m -> [32m0[m bytes
 .../types/__pycache__/base.cpython-312.pyc         |    Bin [31m7788[m -> [32m0[m bytes
 .../__pycache__/chat_completion.cpython-312.pyc    |    Bin [31m12260[m -> [32m0[m bytes
 .../__pycache__/depth_estimation.cpython-312.pyc   |    Bin [31m1092[m -> [32m0[m bytes
 .../document_question_answering.cpython-312.pyc    |    Bin [31m2392[m -> [32m0[m bytes
 .../__pycache__/feature_extraction.cpython-312.pyc |    Bin [31m1236[m -> [32m0[m bytes
 .../types/__pycache__/fill_mask.cpython-312.pyc    |    Bin [31m1577[m -> [32m0[m bytes
 .../image_classification.cpython-312.pyc           |    Bin [31m1599[m -> [32m0[m bytes
 .../__pycache__/image_segmentation.cpython-312.pyc |    Bin [31m1800[m -> [32m0[m bytes
 .../__pycache__/image_to_image.cpython-312.pyc     |    Bin [31m2052[m -> [32m0[m bytes
 .../__pycache__/image_to_text.cpython-312.pyc      |    Bin [31m2859[m -> [32m0[m bytes
 .../__pycache__/image_to_video.cpython-312.pyc     |    Bin [31m2036[m -> [32m0[m bytes
 .../__pycache__/object_detection.cpython-312.pyc   |    Bin [31m1865[m -> [32m0[m bytes
 .../__pycache__/question_answering.cpython-312.pyc |    Bin [31m2174[m -> [32m0[m bytes
 .../sentence_similarity.cpython-312.pyc            |    Bin [31m1070[m -> [32m0[m bytes
 .../__pycache__/summarization.cpython-312.pyc      |    Bin [31m1676[m -> [32m0[m bytes
 .../table_question_answering.cpython-312.pyc       |    Bin [31m2151[m -> [32m0[m bytes
 .../text2text_generation.cpython-312.pyc           |    Bin [31m1827[m -> [32m0[m bytes
 .../text_classification.cpython-312.pyc            |    Bin [31m1587[m -> [32m0[m bytes
 .../__pycache__/text_generation.cpython-312.pyc    |    Bin [31m6164[m -> [32m0[m bytes
 .../__pycache__/text_to_audio.cpython-312.pyc      |    Bin [31m2749[m -> [32m0[m bytes
 .../__pycache__/text_to_image.cpython-312.pyc      |    Bin [31m1702[m -> [32m0[m bytes
 .../__pycache__/text_to_speech.cpython-312.pyc     |    Bin [31m2786[m -> [32m0[m bytes
 .../__pycache__/text_to_video.cpython-312.pyc      |    Bin [31m1617[m -> [32m0[m bytes
 .../token_classification.cpython-312.pyc           |    Bin [31m1869[m -> [32m0[m bytes
 .../types/__pycache__/translation.cpython-312.pyc  |    Bin [31m1780[m -> [32m0[m bytes
 .../video_classification.cpython-312.pyc           |    Bin [31m1734[m -> [32m0[m bytes
 .../visual_question_answering.cpython-312.pyc      |    Bin [31m1821[m -> [32m0[m bytes
 .../zero_shot_classification.cpython-312.pyc       |    Bin [31m1551[m -> [32m0[m bytes
 .../zero_shot_image_classification.cpython-312.pyc |    Bin [31m1523[m -> [32m0[m bytes
 .../zero_shot_object_detection.cpython-312.pyc     |    Bin [31m1835[m -> [32m0[m bytes
 .../_generated/types/audio_classification.py       |     43 [31m-[m
 .../inference/_generated/types/audio_to_audio.py   |     30 [31m-[m
 .../types/automatic_speech_recognition.py          |    113 [31m-[m
 .../inference/_generated/types/base.py             |    164 [31m-[m
 .../inference/_generated/types/chat_completion.py  |    347 [31m-[m
 .../inference/_generated/types/depth_estimation.py |     28 [31m-[m
 .../types/document_question_answering.py           |     80 [31m-[m
 .../_generated/types/feature_extraction.py         |     36 [31m-[m
 .../inference/_generated/types/fill_mask.py        |     47 [31m-[m
 .../_generated/types/image_classification.py       |     43 [31m-[m
 .../_generated/types/image_segmentation.py         |     51 [31m-[m
 .../inference/_generated/types/image_to_image.py   |     60 [31m-[m
 .../inference/_generated/types/image_to_text.py    |    100 [31m-[m
 .../inference/_generated/types/image_to_video.py   |     60 [31m-[m
 .../inference/_generated/types/object_detection.py |     58 [31m-[m
 .../_generated/types/question_answering.py         |     74 [31m-[m
 .../_generated/types/sentence_similarity.py        |     27 [31m-[m
 .../inference/_generated/types/summarization.py    |     41 [31m-[m
 .../_generated/types/table_question_answering.py   |     62 [31m-[m
 .../_generated/types/text2text_generation.py       |     42 [31m-[m
 .../_generated/types/text_classification.py        |     41 [31m-[m
 .../inference/_generated/types/text_generation.py  |    168 [31m-[m
 .../inference/_generated/types/text_to_audio.py    |     99 [31m-[m
 .../inference/_generated/types/text_to_image.py    |     50 [31m-[m
 .../inference/_generated/types/text_to_speech.py   |     99 [31m-[m
 .../inference/_generated/types/text_to_video.py    |     46 [31m-[m
 .../_generated/types/token_classification.py       |     51 [31m-[m
 .../inference/_generated/types/translation.py      |     49 [31m-[m
 .../_generated/types/video_classification.py       |     45 [31m-[m
 .../_generated/types/visual_question_answering.py  |     49 [31m-[m
 .../_generated/types/zero_shot_classification.py   |     45 [31m-[m
 .../types/zero_shot_image_classification.py        |     40 [31m-[m
 .../_generated/types/zero_shot_object_detection.py |     50 [31m-[m
 .../huggingface_hub/inference/_mcp/__init__.py     |      0
 .../_mcp/__pycache__/__init__.cpython-312.pyc      |    Bin [31m192[m -> [32m0[m bytes
 .../_mcp/__pycache__/_cli_hacks.cpython-312.pyc    |    Bin [31m4061[m -> [32m0[m bytes
 .../_mcp/__pycache__/agent.cpython-312.pyc         |    Bin [31m5379[m -> [32m0[m bytes
 .../inference/_mcp/__pycache__/cli.cpython-312.pyc |    Bin [31m12746[m -> [32m0[m bytes
 .../_mcp/__pycache__/constants.cpython-312.pyc     |    Bin [31m2440[m -> [32m0[m bytes
 .../_mcp/__pycache__/mcp_client.cpython-312.pyc    |    Bin [31m18425[m -> [32m0[m bytes
 .../_mcp/__pycache__/types.cpython-312.pyc         |    Bin [31m2055[m -> [32m0[m bytes
 .../_mcp/__pycache__/utils.cpython-312.pyc         |    Bin [31m5495[m -> [32m0[m bytes
 .../huggingface_hub/inference/_mcp/_cli_hacks.py   |     88 [31m-[m
 .../huggingface_hub/inference/_mcp/agent.py        |    100 [31m-[m
 .../huggingface_hub/inference/_mcp/cli.py          |    255 [31m-[m
 .../huggingface_hub/inference/_mcp/constants.py    |     81 [31m-[m
 .../huggingface_hub/inference/_mcp/mcp_client.py   |    395 [31m-[m
 .../huggingface_hub/inference/_mcp/types.py        |     45 [31m-[m
 .../huggingface_hub/inference/_mcp/utils.py        |    128 [31m-[m
 .../inference/_providers/__init__.py               |    266 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m8780[m -> [32m0[m bytes
 .../_providers/__pycache__/_common.cpython-312.pyc |    Bin [31m16871[m -> [32m0[m bytes
 .../__pycache__/black_forest_labs.cpython-312.pyc  |    Bin [31m4407[m -> [32m0[m bytes
 .../__pycache__/cerebras.cpython-312.pyc           |    Bin [31m757[m -> [32m0[m bytes
 .../__pycache__/clarifai.cpython-312.pyc           |    Bin [31m1086[m -> [32m0[m bytes
 .../_providers/__pycache__/cohere.cpython-312.pyc  |    Bin [31m2037[m -> [32m0[m bytes
 .../_providers/__pycache__/fal_ai.cpython-312.pyc  |    Bin [31m16069[m -> [32m0[m bytes
 .../__pycache__/featherless_ai.cpython-312.pyc     |    Bin [31m2679[m -> [32m0[m bytes
 .../__pycache__/fireworks_ai.cpython-312.pyc       |    Bin [31m2000[m -> [32m0[m bytes
 .../_providers/__pycache__/groq.cpython-312.pyc    |    Bin [31m988[m -> [32m0[m bytes
 .../__pycache__/hf_inference.cpython-312.pyc       |    Bin [31m11285[m -> [32m0[m bytes
 .../__pycache__/hyperbolic.cpython-312.pyc         |    Bin [31m3198[m -> [32m0[m bytes
 .../_providers/__pycache__/nebius.cpython-312.pyc  |    Bin [31m5831[m -> [32m0[m bytes
 .../_providers/__pycache__/novita.cpython-312.pyc  |    Bin [31m4358[m -> [32m0[m bytes
 .../_providers/__pycache__/nscale.cpython-312.pyc  |    Bin [31m3022[m -> [32m0[m bytes
 .../_providers/__pycache__/openai.cpython-312.pyc  |    Bin [31m1873[m -> [32m0[m bytes
 .../__pycache__/ovhcloud.cpython-312.pyc           |    Bin [31m883[m -> [32m0[m bytes
 .../__pycache__/publicai.cpython-312.pyc           |    Bin [31m757[m -> [32m0[m bytes
 .../__pycache__/replicate.cpython-312.pyc          |    Bin [31m8396[m -> [32m0[m bytes
 .../__pycache__/sambanova.cpython-312.pyc          |    Bin [31m3479[m -> [32m0[m bytes
 .../__pycache__/scaleway.cpython-312.pyc           |    Bin [31m2596[m -> [32m0[m bytes
 .../__pycache__/together.cpython-312.pyc           |    Bin [31m5524[m -> [32m0[m bytes
 .../__pycache__/wavespeed.cpython-312.pyc          |    Bin [31m7211[m -> [32m0[m bytes
 .../_providers/__pycache__/zai_org.cpython-312.pyc |    Bin [31m1483[m -> [32m0[m bytes
 .../inference/_providers/_common.py                |    363 [31m-[m
 .../inference/_providers/black_forest_labs.py      |     69 [31m-[m
 .../inference/_providers/cerebras.py               |      6 [31m-[m
 .../inference/_providers/clarifai.py               |     13 [31m-[m
 .../huggingface_hub/inference/_providers/cohere.py |     32 [31m-[m
 .../huggingface_hub/inference/_providers/fal_ai.py |    299 [31m-[m
 .../inference/_providers/featherless_ai.py         |     38 [31m-[m
 .../inference/_providers/fireworks_ai.py           |     27 [31m-[m
 .../huggingface_hub/inference/_providers/groq.py   |      9 [31m-[m
 .../inference/_providers/hf_inference.py           |    228 [31m-[m
 .../inference/_providers/hyperbolic.py             |     47 [31m-[m
 .../huggingface_hub/inference/_providers/nebius.py |     83 [31m-[m
 .../huggingface_hub/inference/_providers/novita.py |     69 [31m-[m
 .../huggingface_hub/inference/_providers/nscale.py |     44 [31m-[m
 .../huggingface_hub/inference/_providers/openai.py |     25 [31m-[m
 .../inference/_providers/ovhcloud.py               |     10 [31m-[m
 .../inference/_providers/publicai.py               |      6 [31m-[m
 .../inference/_providers/replicate.py              |    151 [31m-[m
 .../inference/_providers/sambanova.py              |     42 [31m-[m
 .../inference/_providers/scaleway.py               |     28 [31m-[m
 .../inference/_providers/together.py               |     88 [31m-[m
 .../inference/_providers/wavespeed.py              |    138 [31m-[m
 .../inference/_providers/zai_org.py                |     17 [31m-[m
 .../venv/Lib/site-packages/huggingface_hub/lfs.py  |    393 [31m-[m
 .../Lib/site-packages/huggingface_hub/py.typed     |      0
 .../Lib/site-packages/huggingface_hub/repocard.py  |    826 [31m-[m
 .../site-packages/huggingface_hub/repocard_data.py |    770 [31m-[m
 .../huggingface_hub/serialization/__init__.py      |     26 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m607[m -> [32m0[m bytes
 .../__pycache__/_base.cpython-312.pyc              |    Bin [31m7188[m -> [32m0[m bytes
 .../__pycache__/_dduf.cpython-312.pyc              |    Bin [31m19516[m -> [32m0[m bytes
 .../__pycache__/_torch.cpython-312.pyc             |    Bin [31m46266[m -> [32m0[m bytes
 .../huggingface_hub/serialization/_base.py         |    207 [31m-[m
 .../huggingface_hub/serialization/_dduf.py         |    387 [31m-[m
 .../huggingface_hub/serialization/_torch.py        |   1015 [31m-[m
 .../templates/datasetcard_template.md              |    143 [31m-[m
 .../templates/modelcard_template.md                |    200 [31m-[m
 .../huggingface_hub/utils/__init__.py              |    131 [31m-[m
 .../utils/__pycache__/__init__.cpython-312.pyc     |    Bin [31m4285[m -> [32m0[m bytes
 .../utils/__pycache__/_auth.cpython-312.pyc        |    Bin [31m8804[m -> [32m0[m bytes
 .../__pycache__/_cache_assets.cpython-312.pyc      |    Bin [31m5571[m -> [32m0[m bytes
 .../__pycache__/_cache_manager.cpython-312.pyc     |    Bin [31m35967[m -> [32m0[m bytes
 .../utils/__pycache__/_chunk_utils.cpython-312.pyc |    Bin [31m2059[m -> [32m0[m bytes
 .../utils/__pycache__/_datetime.cpython-312.pyc    |    Bin [31m2196[m -> [32m0[m bytes
 .../utils/__pycache__/_deprecation.cpython-312.pyc |    Bin [31m6663[m -> [32m0[m bytes
 .../utils/__pycache__/_dotenv.cpython-312.pyc      |    Bin [31m2495[m -> [32m0[m bytes
 .../__pycache__/_experimental.cpython-312.pyc      |    Bin [31m2349[m -> [32m0[m bytes
 .../utils/__pycache__/_fixes.cpython-312.pyc       |    Bin [31m5467[m -> [32m0[m bytes
 .../__pycache__/_git_credential.cpython-312.pyc    |    Bin [31m5116[m -> [32m0[m bytes
 .../utils/__pycache__/_headers.cpython-312.pyc     |    Bin [31m7855[m -> [32m0[m bytes
 .../utils/__pycache__/_http.cpython-312.pyc        |    Bin [31m37501[m -> [32m0[m bytes
 .../utils/__pycache__/_lfs.cpython-312.pyc         |    Bin [31m5306[m -> [32m0[m bytes
 .../utils/__pycache__/_pagination.cpython-312.pyc  |    Bin [31m2067[m -> [32m0[m bytes
 .../utils/__pycache__/_parsing.cpython-312.pyc     |    Bin [31m3266[m -> [32m0[m bytes
 .../utils/__pycache__/_paths.cpython-312.pyc       |    Bin [31m5139[m -> [32m0[m bytes
 .../utils/__pycache__/_runtime.cpython-312.pyc     |    Bin [31m15140[m -> [32m0[m bytes
 .../utils/__pycache__/_safetensors.cpython-312.pyc |    Bin [31m5885[m -> [32m0[m bytes
 .../utils/__pycache__/_subprocess.cpython-312.pyc  |    Bin [31m5093[m -> [32m0[m bytes
 .../utils/__pycache__/_telemetry.cpython-312.pyc   |    Bin [31m5679[m -> [32m0[m bytes
 .../utils/__pycache__/_terminal.cpython-312.pyc    |    Bin [31m3880[m -> [32m0[m bytes
 .../utils/__pycache__/_typing.cpython-312.pyc      |    Bin [31m4316[m -> [32m0[m bytes
 .../utils/__pycache__/_validators.cpython-312.pyc  |    Bin [31m8426[m -> [32m0[m bytes
 .../__pycache__/_verification.cpython-312.pyc      |    Bin [31m7567[m -> [32m0[m bytes
 .../utils/__pycache__/_xet.cpython-312.pyc         |    Bin [31m11337[m -> [32m0[m bytes
 .../_xet_progress_reporting.cpython-312.pyc        |    Bin [31m7289[m -> [32m0[m bytes
 .../__pycache__/endpoint_helpers.cpython-312.pyc   |    Bin [31m2127[m -> [32m0[m bytes
 .../__pycache__/insecure_hashlib.cpython-312.pyc   |    Bin [31m539[m -> [32m0[m bytes
 .../utils/__pycache__/logging.cpython-312.pyc      |    Bin [31m6083[m -> [32m0[m bytes
 .../utils/__pycache__/sha.cpython-312.pyc          |    Bin [31m2664[m -> [32m0[m bytes
 .../utils/__pycache__/tqdm.cpython-312.pyc         |    Bin [31m11245[m -> [32m0[m bytes
 .../site-packages/huggingface_hub/utils/_auth.py   |    214 [31m-[m
 .../huggingface_hub/utils/_cache_assets.py         |    135 [31m-[m
 .../huggingface_hub/utils/_cache_manager.py        |    841 [31m-[m
 .../huggingface_hub/utils/_chunk_utils.py          |     64 [31m-[m
 .../huggingface_hub/utils/_datetime.py             |     67 [31m-[m
 .../huggingface_hub/utils/_deprecation.py          |    136 [31m-[m
 .../site-packages/huggingface_hub/utils/_dotenv.py |     55 [31m-[m
 .../huggingface_hub/utils/_experimental.py         |     68 [31m-[m
 .../site-packages/huggingface_hub/utils/_fixes.py  |    123 [31m-[m
 .../huggingface_hub/utils/_git_credential.py       |    121 [31m-[m
 .../huggingface_hub/utils/_headers.py              |    206 [31m-[m
 .../site-packages/huggingface_hub/utils/_http.py   |    946 [31m-[m
 .../site-packages/huggingface_hub/utils/_lfs.py    |    110 [31m-[m
 .../huggingface_hub/utils/_pagination.py           |     52 [31m-[m
 .../huggingface_hub/utils/_parsing.py              |     98 [31m-[m
 .../site-packages/huggingface_hub/utils/_paths.py  |    141 [31m-[m
 .../huggingface_hub/utils/_runtime.py              |    431 [31m-[m
 .../huggingface_hub/utils/_safetensors.py          |    111 [31m-[m
 .../huggingface_hub/utils/_subprocess.py           |    144 [31m-[m
 .../huggingface_hub/utils/_telemetry.py            |    126 [31m-[m
 .../huggingface_hub/utils/_terminal.py             |     79 [31m-[m
 .../site-packages/huggingface_hub/utils/_typing.py |     95 [31m-[m
 .../huggingface_hub/utils/_validators.py           |    207 [31m-[m
 .../huggingface_hub/utils/_verification.py         |    167 [31m-[m
 .../site-packages/huggingface_hub/utils/_xet.py    |    235 [31m-[m
 .../utils/_xet_progress_reporting.py               |    162 [31m-[m
 .../huggingface_hub/utils/endpoint_helpers.py      |     66 [31m-[m
 .../huggingface_hub/utils/insecure_hashlib.py      |     32 [31m-[m
 .../site-packages/huggingface_hub/utils/logging.py |    185 [31m-[m
 .../Lib/site-packages/huggingface_hub/utils/sha.py |     64 [31m-[m
 .../site-packages/huggingface_hub/utils/tqdm.py    |    308 [31m-[m
 .../site-packages/idna-3.11.dist-info/INSTALLER    |      1 [31m-[m
 .../Lib/site-packages/idna-3.11.dist-info/METADATA |    209 [31m-[m
 .../Lib/site-packages/idna-3.11.dist-info/RECORD   |     22 [31m-[m
 .../Lib/site-packages/idna-3.11.dist-info/WHEEL    |      4 [31m-[m
 .../idna-3.11.dist-info/licenses/LICENSE.md        |     31 [31m-[m
 backend/venv/Lib/site-packages/idna/__init__.py    |     45 [31m-[m
 .../idna/__pycache__/__init__.cpython-312.pyc      |    Bin [31m864[m -> [32m0[m bytes
 .../idna/__pycache__/codec.cpython-312.pyc         |    Bin [31m4954[m -> [32m0[m bytes
 .../idna/__pycache__/compat.cpython-312.pyc        |    Bin [31m868[m -> [32m0[m bytes
 .../idna/__pycache__/core.cpython-312.pyc          |    Bin [31m16121[m -> [32m0[m bytes
 .../idna/__pycache__/idnadata.cpython-312.pyc      |    Bin [31m100893[m -> [32m0[m bytes
 .../idna/__pycache__/intranges.cpython-312.pyc     |    Bin [31m2611[m -> [32m0[m bytes
 .../idna/__pycache__/package_data.cpython-312.pyc  |    Bin [31m195[m -> [32m0[m bytes
 .../idna/__pycache__/uts46data.cpython-312.pyc     |    Bin [31m161823[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/idna/codec.py       |    122 [31m-[m
 backend/venv/Lib/site-packages/idna/compat.py      |     15 [31m-[m
 backend/venv/Lib/site-packages/idna/core.py        |    437 [31m-[m
 backend/venv/Lib/site-packages/idna/idnadata.py    |   4309 [31m-[m
 backend/venv/Lib/site-packages/idna/intranges.py   |     57 [31m-[m
 .../venv/Lib/site-packages/idna/package_data.py    |      1 [31m-[m
 backend/venv/Lib/site-packages/idna/py.typed       |      0
 backend/venv/Lib/site-packages/idna/uts46data.py   |   8841 [31m--[m
 .../iniconfig-2.3.0.dist-info/INSTALLER            |      1 [31m-[m
 .../iniconfig-2.3.0.dist-info/METADATA             |     79 [31m-[m
 .../site-packages/iniconfig-2.3.0.dist-info/RECORD |     15 [31m-[m
 .../site-packages/iniconfig-2.3.0.dist-info/WHEEL  |      5 [31m-[m
 .../iniconfig-2.3.0.dist-info/licenses/LICENSE     |     21 [31m-[m
 .../iniconfig-2.3.0.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/iniconfig/__init__.py   |    249 [31m-[m
 .../iniconfig/__pycache__/__init__.cpython-312.pyc |    Bin [31m10840[m -> [32m0[m bytes
 .../iniconfig/__pycache__/_parse.cpython-312.pyc   |    Bin [31m5539[m -> [32m0[m bytes
 .../iniconfig/__pycache__/_version.cpython-312.pyc |    Bin [31m779[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m1183[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/iniconfig/_parse.py |    163 [31m-[m
 .../venv/Lib/site-packages/iniconfig/_version.py   |     34 [31m-[m
 .../venv/Lib/site-packages/iniconfig/exceptions.py |     16 [31m-[m
 backend/venv/Lib/site-packages/iniconfig/py.typed  |      0
 .../site-packages/jinja2-3.1.6.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/jinja2-3.1.6.dist-info/METADATA  |     84 [31m-[m
 .../site-packages/jinja2-3.1.6.dist-info/RECORD    |     58 [31m-[m
 .../site-packages/jinja2-3.1.6.dist-info/REQUESTED |      0
 .../Lib/site-packages/jinja2-3.1.6.dist-info/WHEEL |      4 [31m-[m
 .../jinja2-3.1.6.dist-info/entry_points.txt        |      3 [31m-[m
 .../jinja2-3.1.6.dist-info/licenses/LICENSE.txt    |     28 [31m-[m
 backend/venv/Lib/site-packages/jinja2/__init__.py  |     38 [31m-[m
 .../jinja2/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1637[m -> [32m0[m bytes
 .../jinja2/__pycache__/_identifier.cpython-312.pyc |    Bin [31m2118[m -> [32m0[m bytes
 .../jinja2/__pycache__/async_utils.cpython-312.pyc |    Bin [31m4958[m -> [32m0[m bytes
 .../jinja2/__pycache__/bccache.cpython-312.pyc     |    Bin [31m19309[m -> [32m0[m bytes
 .../jinja2/__pycache__/compiler.cpython-312.pyc    |    Bin [31m103876[m -> [32m0[m bytes
 .../jinja2/__pycache__/constants.cpython-312.pyc   |    Bin [31m1540[m -> [32m0[m bytes
 .../jinja2/__pycache__/debug.cpython-312.pyc       |    Bin [31m6550[m -> [32m0[m bytes
 .../jinja2/__pycache__/defaults.cpython-312.pyc    |    Bin [31m1590[m -> [32m0[m bytes
 .../jinja2/__pycache__/environment.cpython-312.pyc |    Bin [31m76619[m -> [32m0[m bytes
 .../jinja2/__pycache__/exceptions.cpython-312.pyc  |    Bin [31m7699[m -> [32m0[m bytes
 .../jinja2/__pycache__/ext.cpython-312.pyc         |    Bin [31m41861[m -> [32m0[m bytes
 .../jinja2/__pycache__/filters.cpython-312.pyc     |    Bin [31m72253[m -> [32m0[m bytes
 .../jinja2/__pycache__/idtracking.cpython-312.pyc  |    Bin [31m19104[m -> [32m0[m bytes
 .../jinja2/__pycache__/lexer.cpython-312.pyc       |    Bin [31m32049[m -> [32m0[m bytes
 .../jinja2/__pycache__/loaders.cpython-312.pyc     |    Bin [31m32259[m -> [32m0[m bytes
 .../jinja2/__pycache__/meta.cpython-312.pyc        |    Bin [31m5454[m -> [32m0[m bytes
 .../jinja2/__pycache__/nativetypes.cpython-312.pyc |    Bin [31m7003[m -> [32m0[m bytes
 .../jinja2/__pycache__/nodes.cpython-312.pyc       |    Bin [31m58203[m -> [32m0[m bytes
 .../jinja2/__pycache__/optimizer.cpython-312.pyc   |    Bin [31m2673[m -> [32m0[m bytes
 .../jinja2/__pycache__/parser.cpython-312.pyc      |    Bin [31m61164[m -> [32m0[m bytes
 .../jinja2/__pycache__/runtime.cpython-312.pyc     |    Bin [31m48868[m -> [32m0[m bytes
 .../jinja2/__pycache__/sandbox.cpython-312.pyc     |    Bin [31m18081[m -> [32m0[m bytes
 .../jinja2/__pycache__/tests.cpython-312.pyc       |    Bin [31m9034[m -> [32m0[m bytes
 .../jinja2/__pycache__/utils.cpython-312.pyc       |    Bin [31m34782[m -> [32m0[m bytes
 .../jinja2/__pycache__/visitor.cpython-312.pyc     |    Bin [31m5337[m -> [32m0[m bytes
 .../venv/Lib/site-packages/jinja2/_identifier.py   |      6 [31m-[m
 .../venv/Lib/site-packages/jinja2/async_utils.py   |     99 [31m-[m
 backend/venv/Lib/site-packages/jinja2/bccache.py   |    408 [31m-[m
 backend/venv/Lib/site-packages/jinja2/compiler.py  |   1998 [31m-[m
 backend/venv/Lib/site-packages/jinja2/constants.py |     20 [31m-[m
 backend/venv/Lib/site-packages/jinja2/debug.py     |    191 [31m-[m
 backend/venv/Lib/site-packages/jinja2/defaults.py  |     48 [31m-[m
 .../venv/Lib/site-packages/jinja2/environment.py   |   1672 [31m-[m
 .../venv/Lib/site-packages/jinja2/exceptions.py    |    166 [31m-[m
 backend/venv/Lib/site-packages/jinja2/ext.py       |    870 [31m-[m
 backend/venv/Lib/site-packages/jinja2/filters.py   |   1873 [31m-[m
 .../venv/Lib/site-packages/jinja2/idtracking.py    |    318 [31m-[m
 backend/venv/Lib/site-packages/jinja2/lexer.py     |    868 [31m-[m
 backend/venv/Lib/site-packages/jinja2/loaders.py   |    693 [31m-[m
 backend/venv/Lib/site-packages/jinja2/meta.py      |    112 [31m-[m
 .../venv/Lib/site-packages/jinja2/nativetypes.py   |    130 [31m-[m
 backend/venv/Lib/site-packages/jinja2/nodes.py     |   1206 [31m-[m
 backend/venv/Lib/site-packages/jinja2/optimizer.py |     48 [31m-[m
 backend/venv/Lib/site-packages/jinja2/parser.py    |   1049 [31m-[m
 backend/venv/Lib/site-packages/jinja2/py.typed     |      0
 backend/venv/Lib/site-packages/jinja2/runtime.py   |   1062 [31m-[m
 backend/venv/Lib/site-packages/jinja2/sandbox.py   |    436 [31m-[m
 backend/venv/Lib/site-packages/jinja2/tests.py     |    256 [31m-[m
 backend/venv/Lib/site-packages/jinja2/utils.py     |    766 [31m-[m
 backend/venv/Lib/site-packages/jinja2/visitor.py   |     92 [31m-[m
 backend/venv/Lib/site-packages/jose/__init__.py    |     10 [31m-[m
 .../jose/__pycache__/__init__.cpython-312.pyc      |    Bin [31m470[m -> [32m0[m bytes
 .../jose/__pycache__/constants.cpython-312.pyc     |    Bin [31m3142[m -> [32m0[m bytes
 .../jose/__pycache__/exceptions.cpython-312.pyc    |    Bin [31m2263[m -> [32m0[m bytes
 .../jose/__pycache__/jwe.cpython-312.pyc           |    Bin [31m19402[m -> [32m0[m bytes
 .../jose/__pycache__/jwk.cpython-312.pyc           |    Bin [31m2447[m -> [32m0[m bytes
 .../jose/__pycache__/jws.cpython-312.pyc           |    Bin [31m9744[m -> [32m0[m bytes
 .../jose/__pycache__/jwt.cpython-312.pyc           |    Bin [31m20677[m -> [32m0[m bytes
 .../jose/__pycache__/utils.cpython-312.pyc         |    Bin [31m6823[m -> [32m0[m bytes
 .../Lib/site-packages/jose/backends/__init__.py    |     26 [31m-[m
 .../backends/__pycache__/__init__.cpython-312.pyc  |    Bin [31m1010[m -> [32m0[m bytes
 .../backends/__pycache__/_asn1.cpython-312.pyc     |    Bin [31m4177[m -> [32m0[m bytes
 .../jose/backends/__pycache__/base.cpython-312.pyc |    Bin [31m3585[m -> [32m0[m bytes
 .../cryptography_backend.cpython-312.pyc           |    Bin [31m32578[m -> [32m0[m bytes
 .../__pycache__/ecdsa_backend.cpython-312.pyc      |    Bin [31m8144[m -> [32m0[m bytes
 .../backends/__pycache__/native.cpython-312.pyc    |    Bin [31m3731[m -> [32m0[m bytes
 .../__pycache__/rsa_backend.cpython-312.pyc        |    Bin [31m13098[m -> [32m0[m bytes
 .../venv/Lib/site-packages/jose/backends/_asn1.py  |     84 [31m-[m
 .../venv/Lib/site-packages/jose/backends/base.py   |     89 [31m-[m
 .../jose/backends/cryptography_backend.py          |    586 [31m-[m
 .../site-packages/jose/backends/ecdsa_backend.py   |    150 [31m-[m
 .../venv/Lib/site-packages/jose/backends/native.py |     69 [31m-[m
 .../Lib/site-packages/jose/backends/rsa_backend.py |    283 [31m-[m
 backend/venv/Lib/site-packages/jose/constants.py   |    100 [31m-[m
 backend/venv/Lib/site-packages/jose/exceptions.py  |     59 [31m-[m
 backend/venv/Lib/site-packages/jose/jwe.py         |    619 [31m-[m
 backend/venv/Lib/site-packages/jose/jwk.py         |     79 [31m-[m
 backend/venv/Lib/site-packages/jose/jws.py         |    268 [31m-[m
 backend/venv/Lib/site-packages/jose/jwt.py         |    512 [31m-[m
 backend/venv/Lib/site-packages/jose/utils.py       |    165 [31m-[m
 .../site-packages/lxml-6.0.2.dist-info/INSTALLER   |      1 [31m-[m
 .../site-packages/lxml-6.0.2.dist-info/METADATA    |    103 [31m-[m
 .../Lib/site-packages/lxml-6.0.2.dist-info/RECORD  |    208 [31m-[m
 .../site-packages/lxml-6.0.2.dist-info/REQUESTED   |      0
 .../Lib/site-packages/lxml-6.0.2.dist-info/WHEEL   |      5 [31m-[m
 .../lxml-6.0.2.dist-info/licenses/LICENSE.txt      |     31 [31m-[m
 .../lxml-6.0.2.dist-info/licenses/LICENSES.txt     |     29 [31m-[m
 .../lxml-6.0.2.dist-info/top_level.txt             |      1 [31m-[m
 .../venv/Lib/site-packages/lxml/ElementInclude.py  |    244 [31m-[m
 backend/venv/Lib/site-packages/lxml/__init__.py    |     22 [31m-[m
 .../__pycache__/ElementInclude.cpython-312.pyc     |    Bin [31m6058[m -> [32m0[m bytes
 .../lxml/__pycache__/__init__.cpython-312.pyc      |    Bin [31m993[m -> [32m0[m bytes
 .../lxml/__pycache__/_elementpath.cpython-312.pyc  |    Bin [31m10410[m -> [32m0[m bytes
 .../lxml/__pycache__/builder.cpython-312.pyc       |    Bin [31m8057[m -> [32m0[m bytes
 .../lxml/__pycache__/cssselect.cpython-312.pyc     |    Bin [31m4554[m -> [32m0[m bytes
 .../__pycache__/doctestcompare.cpython-312.pyc     |    Bin [31m24251[m -> [32m0[m bytes
 .../lxml/__pycache__/pyclasslookup.cpython-312.pyc |    Bin [31m235[m -> [32m0[m bytes
 .../lxml/__pycache__/sax.cpython-312.pyc           |    Bin [31m12877[m -> [32m0[m bytes
 .../lxml/__pycache__/usedoctest.cpython-312.pyc    |    Bin [31m468[m -> [32m0[m bytes
 .../lxml/_elementpath.cp312-win_amd64.pyd          |    Bin [31m147456[m -> [32m0[m bytes
 .../venv/Lib/site-packages/lxml/_elementpath.py    |    343 [31m-[m
 backend/venv/Lib/site-packages/lxml/apihelpers.pxi |   1801 [31m-[m
 .../site-packages/lxml/builder.cp312-win_amd64.pyd |    Bin [31m89600[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/lxml/builder.py     |    243 [31m-[m
 .../venv/Lib/site-packages/lxml/classlookup.pxi    |    580 [31m-[m
 backend/venv/Lib/site-packages/lxml/cleanup.pxi    |    215 [31m-[m
 backend/venv/Lib/site-packages/lxml/cssselect.py   |    101 [31m-[m
 backend/venv/Lib/site-packages/lxml/debug.pxi      |     36 [31m-[m
 backend/venv/Lib/site-packages/lxml/docloader.pxi  |    178 [31m-[m
 .../venv/Lib/site-packages/lxml/doctestcompare.py  |    488 [31m-[m
 backend/venv/Lib/site-packages/lxml/dtd.pxi        |    479 [31m-[m
 .../site-packages/lxml/etree.cp312-win_amd64.pyd   |    Bin [31m4113408[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/lxml/etree.h        |    244 [31m-[m
 backend/venv/Lib/site-packages/lxml/etree.pyx      |   3853 [31m-[m
 backend/venv/Lib/site-packages/lxml/etree_api.h    |    204 [31m-[m
 backend/venv/Lib/site-packages/lxml/extensions.pxi |    830 [31m-[m
 .../Lib/site-packages/lxml/html/ElementSoup.py     |     10 [31m-[m
 .../venv/Lib/site-packages/lxml/html/__init__.py   |   1927 [31m-[m
 .../html/__pycache__/ElementSoup.cpython-312.pyc   |    Bin [31m604[m -> [32m0[m bytes
 .../lxml/html/__pycache__/__init__.cpython-312.pyc |    Bin [31m80734[m -> [32m0[m bytes
 .../html/__pycache__/_diffcommand.cpython-312.pyc  |    Bin [31m3868[m -> [32m0[m bytes
 .../lxml/html/__pycache__/_difflib.cpython-312.pyc |    Bin [31m76964[m -> [32m0[m bytes
 .../html/__pycache__/_html5builder.cpython-312.pyc |    Bin [31m5800[m -> [32m0[m bytes
 .../html/__pycache__/_setmixin.cpython-312.pyc     |    Bin [31m2508[m -> [32m0[m bytes
 .../lxml/html/__pycache__/builder.cpython-312.pyc  |    Bin [31m7360[m -> [32m0[m bytes
 .../lxml/html/__pycache__/clean.cpython-312.pyc    |    Bin [31m608[m -> [32m0[m bytes
 .../lxml/html/__pycache__/defs.cpython-312.pyc     |    Bin [31m3343[m -> [32m0[m bytes
 .../lxml/html/__pycache__/diff.cpython-312.pyc     |    Bin [31m34963[m -> [32m0[m bytes
 .../lxml/html/__pycache__/formfill.cpython-312.pyc |    Bin [31m12142[m -> [32m0[m bytes
 .../html/__pycache__/html5parser.cpython-312.pyc   |    Bin [31m8977[m -> [32m0[m bytes
 .../html/__pycache__/soupparser.cpython-312.pyc    |    Bin [31m11573[m -> [32m0[m bytes
 .../html/__pycache__/usedoctest.cpython-312.pyc    |    Bin [31m492[m -> [32m0[m bytes
 .../Lib/site-packages/lxml/html/_diffcommand.py    |     86 [31m-[m
 .../lxml/html/_difflib.cp312-win_amd64.pyd         |    Bin [31m388608[m -> [32m0[m bytes
 .../venv/Lib/site-packages/lxml/html/_difflib.py   |   2106 [31m-[m
 .../Lib/site-packages/lxml/html/_html5builder.py   |    100 [31m-[m
 .../venv/Lib/site-packages/lxml/html/_setmixin.py  |     56 [31m-[m
 .../venv/Lib/site-packages/lxml/html/builder.py    |    173 [31m-[m
 backend/venv/Lib/site-packages/lxml/html/clean.py  |     21 [31m-[m
 backend/venv/Lib/site-packages/lxml/html/defs.py   |    135 [31m-[m
 .../lxml/html/diff.cp312-win_amd64.pyd             |    Bin [31m237568[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/lxml/html/diff.py   |    972 [31m-[m
 .../venv/Lib/site-packages/lxml/html/formfill.py   |    299 [31m-[m
 .../Lib/site-packages/lxml/html/html5parser.py     |    260 [31m-[m
 .../venv/Lib/site-packages/lxml/html/soupparser.py |    314 [31m-[m
 .../venv/Lib/site-packages/lxml/html/usedoctest.py |     13 [31m-[m
 .../Lib/site-packages/lxml/includes/__init__.pxd   |      0
 .../Lib/site-packages/lxml/includes/__init__.py    |      0
 .../includes/__pycache__/__init__.cpython-312.pyc  |    Bin [31m175[m -> [32m0[m bytes
 .../venv/Lib/site-packages/lxml/includes/c14n.pxd  |     25 [31m-[m
 .../Lib/site-packages/lxml/includes/config.pxd     |      3 [31m-[m
 .../Lib/site-packages/lxml/includes/dtdvalid.pxd   |     18 [31m-[m
 .../Lib/site-packages/lxml/includes/etree_defs.h   |    390 [31m-[m
 .../site-packages/lxml/includes/etreepublic.pxd    |    237 [31m-[m
 .../lxml/includes/extlibs/__init__.py              |      0
 .../extlibs/__pycache__/__init__.cpython-312.pyc   |    Bin [31m183[m -> [32m0[m bytes
 .../site-packages/lxml/includes/extlibs/zconf.h    |    543 [31m-[m
 .../Lib/site-packages/lxml/includes/extlibs/zlib.h |   1938 [31m-[m
 .../Lib/site-packages/lxml/includes/htmlparser.pxd |     56 [31m-[m
 .../lxml/includes/libexslt/__init__.py             |      0
 .../libexslt/__pycache__/__init__.cpython-312.pyc  |    Bin [31m184[m -> [32m0[m bytes
 .../site-packages/lxml/includes/libexslt/exslt.h   |    108 [31m-[m
 .../lxml/includes/libexslt/exsltconfig.h           |     70 [31m-[m
 .../lxml/includes/libexslt/exsltexports.h          |     63 [31m-[m
 .../lxml/includes/libexslt/libexslt.h              |     29 [31m-[m
 .../lxml/includes/libxml/HTMLparser.h              |    320 [31m-[m
 .../site-packages/lxml/includes/libxml/HTMLtree.h  |    147 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/SAX.h   |    204 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/SAX2.h  |    173 [31m-[m
 .../site-packages/lxml/includes/libxml/__init__.py |      0
 .../libxml/__pycache__/__init__.cpython-312.pyc    |    Bin [31m182[m -> [32m0[m bytes
 .../Lib/site-packages/lxml/includes/libxml/c14n.h  |    128 [31m-[m
 .../site-packages/lxml/includes/libxml/catalog.h   |    182 [31m-[m
 .../site-packages/lxml/includes/libxml/chvalid.h   |    230 [31m-[m
 .../site-packages/lxml/includes/libxml/debugXML.h  |    217 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/dict.h  |     81 [31m-[m
 .../site-packages/lxml/includes/libxml/encoding.h  |    233 [31m-[m
 .../site-packages/lxml/includes/libxml/entities.h  |    151 [31m-[m
 .../site-packages/lxml/includes/libxml/globals.h   |    529 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/hash.h  |    236 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/list.h  |    137 [31m-[m
 .../site-packages/lxml/includes/libxml/nanoftp.h   |    186 [31m-[m
 .../site-packages/lxml/includes/libxml/nanohttp.h  |     81 [31m-[m
 .../site-packages/lxml/includes/libxml/parser.h    |   1265 [31m-[m
 .../lxml/includes/libxml/parserInternals.h         |    662 [31m-[m
 .../site-packages/lxml/includes/libxml/pattern.h   |    100 [31m-[m
 .../site-packages/lxml/includes/libxml/relaxng.h   |    218 [31m-[m
 .../lxml/includes/libxml/schemasInternals.h        |    958 [31m-[m
 .../lxml/includes/libxml/schematron.h              |    142 [31m-[m
 .../site-packages/lxml/includes/libxml/threads.h   |     94 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/tree.h  |   1314 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/uri.h   |     94 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/valid.h |    448 [31m-[m
 .../site-packages/lxml/includes/libxml/xinclude.h  |    129 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/xlink.h |    189 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/xmlIO.h |    369 [31m-[m
 .../lxml/includes/libxml/xmlautomata.h             |    146 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlerror.h  |    919 [31m-[m
 .../lxml/includes/libxml/xmlexports.h              |     50 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlmemory.h |    228 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlmodule.h |     57 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlreader.h |    428 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlregexp.h |    222 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlsave.h   |     88 [31m-[m
 .../lxml/includes/libxml/xmlschemas.h              |    246 [31m-[m
 .../lxml/includes/libxml/xmlschemastypes.h         |    152 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlstring.h |    140 [31m-[m
 .../lxml/includes/libxml/xmlunicode.h              |    202 [31m-[m
 .../lxml/includes/libxml/xmlversion.h              |    526 [31m-[m
 .../site-packages/lxml/includes/libxml/xmlwriter.h |    488 [31m-[m
 .../Lib/site-packages/lxml/includes/libxml/xpath.h |    575 [31m-[m
 .../lxml/includes/libxml/xpathInternals.h          |    632 [31m-[m
 .../site-packages/lxml/includes/libxml/xpointer.h  |    137 [31m-[m
 .../lxml/includes/libxslt/__init__.py              |      0
 .../libxslt/__pycache__/__init__.cpython-312.pyc   |    Bin [31m183[m -> [32m0[m bytes
 .../lxml/includes/libxslt/attributes.h             |     39 [31m-[m
 .../lxml/includes/libxslt/documents.h              |     93 [31m-[m
 .../lxml/includes/libxslt/extensions.h             |    262 [31m-[m
 .../site-packages/lxml/includes/libxslt/extra.h    |     72 [31m-[m
 .../lxml/includes/libxslt/functions.h              |     78 [31m-[m
 .../site-packages/lxml/includes/libxslt/imports.h  |     75 [31m-[m
 .../Lib/site-packages/lxml/includes/libxslt/keys.h |     53 [31m-[m
 .../site-packages/lxml/includes/libxslt/libxslt.h  |     36 [31m-[m
 .../lxml/includes/libxslt/namespaces.h             |     68 [31m-[m
 .../lxml/includes/libxslt/numbersInternals.h       |     73 [31m-[m
 .../site-packages/lxml/includes/libxslt/preproc.h  |     43 [31m-[m
 .../site-packages/lxml/includes/libxslt/security.h |    104 [31m-[m
 .../lxml/includes/libxslt/templates.h              |     77 [31m-[m
 .../lxml/includes/libxslt/transform.h              |    207 [31m-[m
 .../Lib/site-packages/lxml/includes/libxslt/trio.h |    216 [31m-[m
 .../site-packages/lxml/includes/libxslt/triodef.h  |    220 [31m-[m
 .../lxml/includes/libxslt/variables.h              |    118 [31m-[m
 .../lxml/includes/libxslt/win32config.h            |     51 [31m-[m
 .../Lib/site-packages/lxml/includes/libxslt/xslt.h |    110 [31m-[m
 .../lxml/includes/libxslt/xsltInternals.h          |   1992 [31m-[m
 .../lxml/includes/libxslt/xsltconfig.h             |    179 [31m-[m
 .../lxml/includes/libxslt/xsltexports.h            |     64 [31m-[m
 .../lxml/includes/libxslt/xsltlocale.h             |     44 [31m-[m
 .../lxml/includes/libxslt/xsltutils.h              |    343 [31m-[m
 .../Lib/site-packages/lxml/includes/lxml-version.h |      3 [31m-[m
 .../Lib/site-packages/lxml/includes/relaxng.pxd    |     64 [31m-[m
 .../Lib/site-packages/lxml/includes/schematron.pxd |     34 [31m-[m
 .../venv/Lib/site-packages/lxml/includes/tree.pxd  |    492 [31m-[m
 .../venv/Lib/site-packages/lxml/includes/uri.pxd   |      5 [31m-[m
 .../Lib/site-packages/lxml/includes/xinclude.pxd   |     22 [31m-[m
 .../Lib/site-packages/lxml/includes/xmlerror.pxd   |    860 [31m-[m
 .../Lib/site-packages/lxml/includes/xmlparser.pxd  |    318 [31m-[m
 .../Lib/site-packages/lxml/includes/xmlschema.pxd  |     35 [31m-[m
 .../venv/Lib/site-packages/lxml/includes/xpath.pxd |    136 [31m-[m
 .../venv/Lib/site-packages/lxml/includes/xslt.pxd  |    190 [31m-[m
 .../site-packages/lxml/isoschematron/__init__.py   |    348 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m14188[m -> [32m0[m bytes
 .../isoschematron/resources/rng/iso-schematron.rng |    709 [31m-[m
 .../isoschematron/resources/xsl/RNG2Schtrn.xsl     |     75 [31m-[m
 .../isoschematron/resources/xsl/XSD2Schtrn.xsl     |     77 [31m-[m
 .../iso-schematron-xslt1/iso_abstract_expand.xsl   |    313 [31m-[m
 .../xsl/iso-schematron-xslt1/iso_dsdl_include.xsl  |   1160 [31m-[m
 .../iso_schematron_message.xsl                     |     55 [31m-[m
 .../iso_schematron_skeleton_for_xslt1.xsl          |   1796 [31m-[m
 .../iso-schematron-xslt1/iso_svrl_for_xslt1.xsl    |    588 [31m-[m
 .../resources/xsl/iso-schematron-xslt1/readme.txt  |     84 [31m-[m
 backend/venv/Lib/site-packages/lxml/iterparse.pxi  |    438 [31m-[m
 backend/venv/Lib/site-packages/lxml/lxml.etree.h   |    244 [31m-[m
 .../venv/Lib/site-packages/lxml/lxml.etree_api.h   |    204 [31m-[m
 backend/venv/Lib/site-packages/lxml/nsclasses.pxi  |    281 [31m-[m
 .../lxml/objectify.cp312-win_amd64.pyd             |    Bin [31m1754112[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/lxml/objectify.pyx  |   2149 [31m-[m
 backend/venv/Lib/site-packages/lxml/objectpath.pxi |    332 [31m-[m
 backend/venv/Lib/site-packages/lxml/parser.pxi     |   2071 [31m-[m
 .../venv/Lib/site-packages/lxml/parsertarget.pxi   |    180 [31m-[m
 backend/venv/Lib/site-packages/lxml/proxy.pxi      |    622 [31m-[m
 backend/venv/Lib/site-packages/lxml/public-api.pxi |    178 [31m-[m
 .../venv/Lib/site-packages/lxml/pyclasslookup.py   |      3 [31m-[m
 .../venv/Lib/site-packages/lxml/readonlytree.pxi   |    565 [31m-[m
 backend/venv/Lib/site-packages/lxml/relaxng.pxi    |    165 [31m-[m
 .../Lib/site-packages/lxml/sax.cp312-win_amd64.pyd |    Bin [31m122368[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/lxml/sax.py         |    285 [31m-[m
 backend/venv/Lib/site-packages/lxml/saxparser.pxi  |    875 [31m-[m
 backend/venv/Lib/site-packages/lxml/schematron.pxi |    173 [31m-[m
 backend/venv/Lib/site-packages/lxml/serializer.pxi |   1849 [31m-[m
 backend/venv/Lib/site-packages/lxml/usedoctest.py  |     13 [31m-[m
 backend/venv/Lib/site-packages/lxml/xinclude.pxi   |     67 [31m-[m
 backend/venv/Lib/site-packages/lxml/xmlerror.pxi   |   1662 [31m-[m
 backend/venv/Lib/site-packages/lxml/xmlid.pxi      |    179 [31m-[m
 backend/venv/Lib/site-packages/lxml/xmlschema.pxi  |    215 [31m-[m
 backend/venv/Lib/site-packages/lxml/xpath.pxi      |    487 [31m-[m
 backend/venv/Lib/site-packages/lxml/xslt.pxi       |    957 [31m-[m
 backend/venv/Lib/site-packages/lxml/xsltext.pxi    |    242 [31m-[m
 .../site-packages/mako-1.3.10.dist-info/INSTALLER  |      1 [31m-[m
 .../site-packages/mako-1.3.10.dist-info/METADATA   |     88 [31m-[m
 .../Lib/site-packages/mako-1.3.10.dist-info/RECORD |     74 [31m-[m
 .../Lib/site-packages/mako-1.3.10.dist-info/WHEEL  |      5 [31m-[m
 .../mako-1.3.10.dist-info/entry_points.txt         |     18 [31m-[m
 .../mako-1.3.10.dist-info/licenses/LICENSE         |     19 [31m-[m
 .../mako-1.3.10.dist-info/top_level.txt            |      1 [31m-[m
 backend/venv/Lib/site-packages/mako/__init__.py    |      8 [31m-[m
 .../mako/__pycache__/__init__.cpython-312.pyc      |    Bin [31m195[m -> [32m0[m bytes
 .../mako/__pycache__/_ast_util.cpython-312.pyc     |    Bin [31m36272[m -> [32m0[m bytes
 .../mako/__pycache__/ast.cpython-312.pyc           |    Bin [31m7469[m -> [32m0[m bytes
 .../mako/__pycache__/cache.cpython-312.pyc         |    Bin [31m8478[m -> [32m0[m bytes
 .../mako/__pycache__/cmd.cpython-312.pyc           |    Bin [31m3730[m -> [32m0[m bytes
 .../mako/__pycache__/codegen.cpython-312.pyc       |    Bin [31m58948[m -> [32m0[m bytes
 .../mako/__pycache__/compat.cpython-312.pyc        |    Bin [31m3055[m -> [32m0[m bytes
 .../mako/__pycache__/exceptions.cpython-312.pyc    |    Bin [31m14744[m -> [32m0[m bytes
 .../mako/__pycache__/filters.cpython-312.pyc       |    Bin [31m6690[m -> [32m0[m bytes
 .../mako/__pycache__/lexer.cpython-312.pyc         |    Bin [31m20316[m -> [32m0[m bytes
 .../mako/__pycache__/lookup.cpython-312.pyc        |    Bin [31m13690[m -> [32m0[m bytes
 .../mako/__pycache__/parsetree.cpython-312.pyc     |    Bin [31m29947[m -> [32m0[m bytes
 .../mako/__pycache__/pygen.cpython-312.pyc         |    Bin [31m11013[m -> [32m0[m bytes
 .../mako/__pycache__/pyparser.cpython-312.pyc      |    Bin [31m12229[m -> [32m0[m bytes
 .../mako/__pycache__/runtime.cpython-312.pyc       |    Bin [31m39057[m -> [32m0[m bytes
 .../mako/__pycache__/template.cpython-312.pyc      |    Bin [31m26786[m -> [32m0[m bytes
 .../mako/__pycache__/util.cpython-312.pyc          |    Bin [31m20338[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/mako/_ast_util.py   |    713 [31m-[m
 backend/venv/Lib/site-packages/mako/ast.py         |    202 [31m-[m
 backend/venv/Lib/site-packages/mako/cache.py       |    239 [31m-[m
 backend/venv/Lib/site-packages/mako/cmd.py         |     99 [31m-[m
 backend/venv/Lib/site-packages/mako/codegen.py     |   1319 [31m-[m
 backend/venv/Lib/site-packages/mako/compat.py      |     70 [31m-[m
 backend/venv/Lib/site-packages/mako/exceptions.py  |    417 [31m-[m
 .../venv/Lib/site-packages/mako/ext/__init__.py    |      0
 .../mako/ext/__pycache__/__init__.cpython-312.pyc  |    Bin [31m170[m -> [32m0[m bytes
 .../ext/__pycache__/autohandler.cpython-312.pyc    |    Bin [31m2338[m -> [32m0[m bytes
 .../ext/__pycache__/babelplugin.cpython-312.pyc    |    Bin [31m2652[m -> [32m0[m bytes
 .../ext/__pycache__/beaker_cache.cpython-312.pyc   |    Bin [31m3905[m -> [32m0[m bytes
 .../mako/ext/__pycache__/extract.cpython-312.pyc   |    Bin [31m5123[m -> [32m0[m bytes
 .../ext/__pycache__/linguaplugin.cpython-312.pyc   |    Bin [31m2603[m -> [32m0[m bytes
 .../ext/__pycache__/preprocessors.cpython-312.pyc  |    Bin [31m665[m -> [32m0[m bytes
 .../ext/__pycache__/pygmentplugin.cpython-312.pyc  |    Bin [31m5896[m -> [32m0[m bytes
 .../ext/__pycache__/turbogears.cpython-312.pyc     |    Bin [31m2433[m -> [32m0[m bytes
 .../venv/Lib/site-packages/mako/ext/autohandler.py |     70 [31m-[m
 .../venv/Lib/site-packages/mako/ext/babelplugin.py |     57 [31m-[m
 .../Lib/site-packages/mako/ext/beaker_cache.py     |     82 [31m-[m
 backend/venv/Lib/site-packages/mako/ext/extract.py |    129 [31m-[m
 .../Lib/site-packages/mako/ext/linguaplugin.py     |     57 [31m-[m
 .../Lib/site-packages/mako/ext/preprocessors.py    |     20 [31m-[m
 .../Lib/site-packages/mako/ext/pygmentplugin.py    |    150 [31m-[m
 .../venv/Lib/site-packages/mako/ext/turbogears.py  |     61 [31m-[m
 backend/venv/Lib/site-packages/mako/filters.py     |    163 [31m-[m
 backend/venv/Lib/site-packages/mako/lexer.py       |    481 [31m-[m
 backend/venv/Lib/site-packages/mako/lookup.py      |    361 [31m-[m
 backend/venv/Lib/site-packages/mako/parsetree.py   |    656 [31m-[m
 backend/venv/Lib/site-packages/mako/pygen.py       |    309 [31m-[m
 backend/venv/Lib/site-packages/mako/pyparser.py    |    235 [31m-[m
 backend/venv/Lib/site-packages/mako/runtime.py     |    968 [31m-[m
 backend/venv/Lib/site-packages/mako/template.py    |    711 [31m-[m
 .../Lib/site-packages/mako/testing/__init__.py     |      0
 .../testing/__pycache__/__init__.cpython-312.pyc   |    Bin [31m174[m -> [32m0[m bytes
 .../testing/__pycache__/_config.cpython-312.pyc    |    Bin [31m5809[m -> [32m0[m bytes
 .../testing/__pycache__/assertions.cpython-312.pyc |    Bin [31m5880[m -> [32m0[m bytes
 .../testing/__pycache__/config.cpython-312.pyc     |    Bin [31m788[m -> [32m0[m bytes
 .../testing/__pycache__/exclusions.cpython-312.pyc |    Bin [31m2391[m -> [32m0[m bytes
 .../testing/__pycache__/fixtures.cpython-312.pyc   |    Bin [31m4786[m -> [32m0[m bytes
 .../testing/__pycache__/helpers.cpython-312.pyc    |    Bin [31m3482[m -> [32m0[m bytes
 .../venv/Lib/site-packages/mako/testing/_config.py |    128 [31m-[m
 .../Lib/site-packages/mako/testing/assertions.py   |    166 [31m-[m
 .../venv/Lib/site-packages/mako/testing/config.py  |     17 [31m-[m
 .../Lib/site-packages/mako/testing/exclusions.py   |     80 [31m-[m
 .../Lib/site-packages/mako/testing/fixtures.py     |    119 [31m-[m
 .../venv/Lib/site-packages/mako/testing/helpers.py |     71 [31m-[m
 backend/venv/Lib/site-packages/mako/util.py        |    388 [31m-[m
 .../markupsafe-3.0.3.dist-info/INSTALLER           |      1 [31m-[m
 .../markupsafe-3.0.3.dist-info/METADATA            |     74 [31m-[m
 .../markupsafe-3.0.3.dist-info/RECORD              |     14 [31m-[m
 .../site-packages/markupsafe-3.0.3.dist-info/WHEEL |      5 [31m-[m
 .../licenses/LICENSE.txt                           |     28 [31m-[m
 .../markupsafe-3.0.3.dist-info/top_level.txt       |      1 [31m-[m
 .../venv/Lib/site-packages/markupsafe/__init__.py  |    396 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m20972[m -> [32m0[m bytes
 .../markupsafe/__pycache__/_native.cpython-312.pyc |    Bin [31m599[m -> [32m0[m bytes
 .../venv/Lib/site-packages/markupsafe/_native.py   |      8 [31m-[m
 .../venv/Lib/site-packages/markupsafe/_speedups.c  |    200 [31m-[m
 .../markupsafe/_speedups.cp312-win_amd64.pyd       |    Bin [31m13312[m -> [32m0[m bytes
 .../Lib/site-packages/markupsafe/_speedups.pyi     |      1 [31m-[m
 backend/venv/Lib/site-packages/markupsafe/py.typed |      0
 .../multidict-6.7.0.dist-info/INSTALLER            |      1 [31m-[m
 .../multidict-6.7.0.dist-info/METADATA             |    149 [31m-[m
 .../site-packages/multidict-6.7.0.dist-info/RECORD |     16 [31m-[m
 .../site-packages/multidict-6.7.0.dist-info/WHEEL  |      5 [31m-[m
 .../multidict-6.7.0.dist-info/licenses/LICENSE     |     13 [31m-[m
 .../multidict-6.7.0.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/multidict/__init__.py   |     60 [31m-[m
 .../multidict/__pycache__/__init__.cpython-312.pyc |    Bin [31m1381[m -> [32m0[m bytes
 .../multidict/__pycache__/_abc.cpython-312.pyc     |    Bin [31m5543[m -> [32m0[m bytes
 .../multidict/__pycache__/_compat.cpython-312.pyc  |    Bin [31m643[m -> [32m0[m bytes
 .../__pycache__/_multidict_py.cpython-312.pyc      |    Bin [31m65232[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/multidict/_abc.py   |     73 [31m-[m
 .../venv/Lib/site-packages/multidict/_compat.py    |     15 [31m-[m
 .../multidict/_multidict.cp312-win_amd64.pyd       |    Bin [31m80896[m -> [32m0[m bytes
 .../Lib/site-packages/multidict/_multidict_py.py   |   1242 [31m-[m
 backend/venv/Lib/site-packages/multidict/py.typed  |      1 [31m-[m
 .../venv/Lib/site-packages/multipart/__init__.py   |     24 [31m-[m
 .../multipart/__pycache__/__init__.cpython-312.pyc |    Bin [31m1411[m -> [32m0[m bytes
 .../multipart/__pycache__/decoders.cpython-312.pyc |    Bin [31m218[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m222[m -> [32m0[m bytes
 .../__pycache__/multipart.cpython-312.pyc          |    Bin [31m220[m -> [32m0[m bytes
 .../venv/Lib/site-packages/multipart/decoders.py   |      1 [31m-[m
 .../venv/Lib/site-packages/multipart/exceptions.py |      1 [31m-[m
 .../venv/Lib/site-packages/multipart/multipart.py  |      1 [31m-[m
 .../packaging-25.0.dist-info/INSTALLER             |      1 [31m-[m
 .../packaging-25.0.dist-info/METADATA              |    105 [31m-[m
 .../site-packages/packaging-25.0.dist-info/RECORD  |     40 [31m-[m
 .../site-packages/packaging-25.0.dist-info/WHEEL   |      4 [31m-[m
 .../packaging-25.0.dist-info/licenses/LICENSE      |      3 [31m-[m
 .../licenses/LICENSE.APACHE                        |    177 [31m-[m
 .../packaging-25.0.dist-info/licenses/LICENSE.BSD  |     23 [31m-[m
 .../venv/Lib/site-packages/packaging/__init__.py   |     15 [31m-[m
 .../packaging/__pycache__/__init__.cpython-312.pyc |    Bin [31m536[m -> [32m0[m bytes
 .../packaging/__pycache__/_elffile.cpython-312.pyc |    Bin [31m4994[m -> [32m0[m bytes
 .../__pycache__/_manylinux.cpython-312.pyc         |    Bin [31m9684[m -> [32m0[m bytes
 .../__pycache__/_musllinux.cpython-312.pyc         |    Bin [31m4532[m -> [32m0[m bytes
 .../packaging/__pycache__/_parser.cpython-312.pyc  |    Bin [31m13961[m -> [32m0[m bytes
 .../__pycache__/_structures.cpython-312.pyc        |    Bin [31m3219[m -> [32m0[m bytes
 .../__pycache__/_tokenizer.cpython-312.pyc         |    Bin [31m7930[m -> [32m0[m bytes
 .../packaging/__pycache__/markers.cpython-312.pyc  |    Bin [31m12744[m -> [32m0[m bytes
 .../packaging/__pycache__/metadata.cpython-312.pyc |    Bin [31m27186[m -> [32m0[m bytes
 .../__pycache__/requirements.cpython-312.pyc       |    Bin [31m4388[m -> [32m0[m bytes
 .../__pycache__/specifiers.cpython-312.pyc         |    Bin [31m38993[m -> [32m0[m bytes
 .../packaging/__pycache__/tags.cpython-312.pyc     |    Bin [31m24651[m -> [32m0[m bytes
 .../packaging/__pycache__/utils.cpython-312.pyc    |    Bin [31m6613[m -> [32m0[m bytes
 .../packaging/__pycache__/version.cpython-312.pyc  |    Bin [31m20452[m -> [32m0[m bytes
 .../venv/Lib/site-packages/packaging/_elffile.py   |    109 [31m-[m
 .../venv/Lib/site-packages/packaging/_manylinux.py |    262 [31m-[m
 .../venv/Lib/site-packages/packaging/_musllinux.py |     85 [31m-[m
 .../venv/Lib/site-packages/packaging/_parser.py    |    353 [31m-[m
 .../Lib/site-packages/packaging/_structures.py     |     61 [31m-[m
 .../venv/Lib/site-packages/packaging/_tokenizer.py |    195 [31m-[m
 .../site-packages/packaging/licenses/__init__.py   |    145 [31m-[m
 .../licenses/__pycache__/__init__.cpython-312.pyc  |    Bin [31m4086[m -> [32m0[m bytes
 .../licenses/__pycache__/_spdx.cpython-312.pyc     |    Bin [31m47342[m -> [32m0[m bytes
 .../Lib/site-packages/packaging/licenses/_spdx.py  |    759 [31m-[m
 .../venv/Lib/site-packages/packaging/markers.py    |    362 [31m-[m
 .../venv/Lib/site-packages/packaging/metadata.py   |    862 [31m-[m
 backend/venv/Lib/site-packages/packaging/py.typed  |      0
 .../Lib/site-packages/packaging/requirements.py    |     91 [31m-[m
 .../venv/Lib/site-packages/packaging/specifiers.py |   1019 [31m-[m
 backend/venv/Lib/site-packages/packaging/tags.py   |    656 [31m-[m
 backend/venv/Lib/site-packages/packaging/utils.py  |    163 [31m-[m
 .../venv/Lib/site-packages/packaging/version.py    |    582 [31m-[m
 .../passlib-1.7.4.dist-info/INSTALLER              |      1 [31m-[m
 .../site-packages/passlib-1.7.4.dist-info/LICENSE  |    116 [31m-[m
 .../site-packages/passlib-1.7.4.dist-info/METADATA |     40 [31m-[m
 .../site-packages/passlib-1.7.4.dist-info/RECORD   |    202 [31m-[m
 .../passlib-1.7.4.dist-info/REQUESTED              |      0
 .../site-packages/passlib-1.7.4.dist-info/WHEEL    |      6 [31m-[m
 .../passlib-1.7.4.dist-info/top_level.txt          |      1 [31m-[m
 .../site-packages/passlib-1.7.4.dist-info/zip-safe |      1 [31m-[m
 backend/venv/Lib/site-packages/passlib/__init__.py |      3 [31m-[m
 .../passlib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m270[m -> [32m0[m bytes
 .../passlib/__pycache__/apache.cpython-312.pyc     |    Bin [31m42678[m -> [32m0[m bytes
 .../passlib/__pycache__/apps.cpython-312.pyc       |    Bin [31m4308[m -> [32m0[m bytes
 .../passlib/__pycache__/context.cpython-312.pyc    |    Bin [31m96228[m -> [32m0[m bytes
 .../passlib/__pycache__/exc.cpython-312.pyc        |    Bin [31m15714[m -> [32m0[m bytes
 .../passlib/__pycache__/hash.cpython-312.pyc       |    Bin [31m2455[m -> [32m0[m bytes
 .../passlib/__pycache__/hosts.cpython-312.pyc      |    Bin [31m1409[m -> [32m0[m bytes
 .../passlib/__pycache__/ifc.cpython-312.pyc        |    Bin [31m7740[m -> [32m0[m bytes
 .../passlib/__pycache__/pwd.cpython-312.pyc        |    Bin [31m26196[m -> [32m0[m bytes
 .../passlib/__pycache__/registry.cpython-312.pyc   |    Bin [31m18596[m -> [32m0[m bytes
 .../passlib/__pycache__/totp.cpython-312.pyc       |    Bin [31m66392[m -> [32m0[m bytes
 .../passlib/__pycache__/win32.cpython-312.pyc      |    Bin [31m2274[m -> [32m0[m bytes
 .../site-packages/passlib/_data/wordsets/bip39.txt |   2049 [31m-[m
 .../passlib/_data/wordsets/eff_long.txt            |   7776 [31m--[m
 .../passlib/_data/wordsets/eff_prefixed.txt        |   1296 [31m-[m
 .../passlib/_data/wordsets/eff_short.txt           |   1296 [31m-[m
 backend/venv/Lib/site-packages/passlib/apache.py   |   1255 [31m-[m
 backend/venv/Lib/site-packages/passlib/apps.py     |    245 [31m-[m
 backend/venv/Lib/site-packages/passlib/context.py  |   2637 [31m-[m
 .../Lib/site-packages/passlib/crypto/__init__.py   |      1 [31m-[m
 .../crypto/__pycache__/__init__.cpython-312.pyc    |    Bin [31m268[m -> [32m0[m bytes
 .../crypto/__pycache__/_md4.cpython-312.pyc        |    Bin [31m7731[m -> [32m0[m bytes
 .../passlib/crypto/__pycache__/des.cpython-312.pyc |    Bin [31m24849[m -> [32m0[m bytes
 .../crypto/__pycache__/digest.cpython-312.pyc      |    Bin [31m30092[m -> [32m0[m bytes
 .../passlib/crypto/_blowfish/__init__.py           |    169 [31m-[m
 .../_blowfish/__pycache__/__init__.cpython-312.pyc |    Bin [31m5394[m -> [32m0[m bytes
 .../__pycache__/_gen_files.cpython-312.pyc         |    Bin [31m7556[m -> [32m0[m bytes
 .../_blowfish/__pycache__/base.cpython-312.pyc     |    Bin [31m14010[m -> [32m0[m bytes
 .../_blowfish/__pycache__/unrolled.cpython-312.pyc |    Bin [31m37174[m -> [32m0[m bytes
 .../passlib/crypto/_blowfish/_gen_files.py         |    204 [31m-[m
 .../site-packages/passlib/crypto/_blowfish/base.py |    441 [31m-[m
 .../passlib/crypto/_blowfish/unrolled.py           |    771 [31m-[m
 .../venv/Lib/site-packages/passlib/crypto/_md4.py  |    244 [31m-[m
 .../venv/Lib/site-packages/passlib/crypto/des.py   |    848 [31m-[m
 .../Lib/site-packages/passlib/crypto/digest.py     |   1057 [31m-[m
 .../passlib/crypto/scrypt/__init__.py              |    281 [31m-[m
 .../scrypt/__pycache__/__init__.cpython-312.pyc    |    Bin [31m7938[m -> [32m0[m bytes
 .../scrypt/__pycache__/_builtin.cpython-312.pyc    |    Bin [31m8120[m -> [32m0[m bytes
 .../scrypt/__pycache__/_gen_files.cpython-312.pyc  |    Bin [31m3669[m -> [32m0[m bytes
 .../scrypt/__pycache__/_salsa.cpython-312.pyc      |    Bin [31m4671[m -> [32m0[m bytes
 .../passlib/crypto/scrypt/_builtin.py              |    244 [31m-[m
 .../passlib/crypto/scrypt/_gen_files.py            |    154 [31m-[m
 .../site-packages/passlib/crypto/scrypt/_salsa.py  |    170 [31m-[m
 backend/venv/Lib/site-packages/passlib/exc.py      |    397 [31m-[m
 .../venv/Lib/site-packages/passlib/ext/__init__.py |      1 [31m-[m
 .../ext/__pycache__/__init__.cpython-312.pyc       |    Bin [31m173[m -> [32m0[m bytes
 .../site-packages/passlib/ext/django/__init__.py   |      6 [31m-[m
 .../django/__pycache__/__init__.cpython-312.pyc    |    Bin [31m418[m -> [32m0[m bytes
 .../ext/django/__pycache__/models.cpython-312.pyc  |    Bin [31m639[m -> [32m0[m bytes
 .../ext/django/__pycache__/utils.cpython-312.pyc   |    Bin [31m38873[m -> [32m0[m bytes
 .../Lib/site-packages/passlib/ext/django/models.py |     36 [31m-[m
 .../Lib/site-packages/passlib/ext/django/utils.py  |   1276 [31m-[m
 .../Lib/site-packages/passlib/handlers/__init__.py |      1 [31m-[m
 .../handlers/__pycache__/__init__.cpython-312.pyc  |    Bin [31m272[m -> [32m0[m bytes
 .../handlers/__pycache__/argon2.cpython-312.pyc    |    Bin [31m30316[m -> [32m0[m bytes
 .../handlers/__pycache__/bcrypt.cpython-312.pyc    |    Bin [31m38929[m -> [32m0[m bytes
 .../handlers/__pycache__/cisco.cpython-312.pyc     |    Bin [31m13023[m -> [32m0[m bytes
 .../handlers/__pycache__/des_crypt.cpython-312.pyc |    Bin [31m20905[m -> [32m0[m bytes
 .../handlers/__pycache__/digests.cpython-312.pyc   |    Bin [31m6325[m -> [32m0[m bytes
 .../handlers/__pycache__/django.cpython-312.pyc    |    Bin [31m21262[m -> [32m0[m bytes
 .../handlers/__pycache__/fshp.cpython-312.pyc      |    Bin [31m7783[m -> [32m0[m bytes
 .../__pycache__/ldap_digests.cpython-312.pyc       |    Bin [31m14310[m -> [32m0[m bytes
 .../handlers/__pycache__/md5_crypt.cpython-312.pyc |    Bin [31m9196[m -> [32m0[m bytes
 .../handlers/__pycache__/misc.cpython-312.pyc      |    Bin [31m11353[m -> [32m0[m bytes
 .../handlers/__pycache__/mssql.cpython-312.pyc     |    Bin [31m9174[m -> [32m0[m bytes
 .../handlers/__pycache__/mysql.cpython-312.pyc     |    Bin [31m4340[m -> [32m0[m bytes
 .../handlers/__pycache__/oracle.cpython-312.pyc    |    Bin [31m6643[m -> [32m0[m bytes
 .../handlers/__pycache__/pbkdf2.cpython-312.pyc    |    Bin [31m17973[m -> [32m0[m bytes
 .../handlers/__pycache__/phpass.cpython-312.pyc    |    Bin [31m4964[m -> [32m0[m bytes
 .../handlers/__pycache__/postgres.cpython-312.pyc  |    Bin [31m2070[m -> [32m0[m bytes
 .../handlers/__pycache__/roundup.cpython-312.pyc   |    Bin [31m935[m -> [32m0[m bytes
 .../handlers/__pycache__/scram.cpython-312.pyc     |    Bin [31m15251[m -> [32m0[m bytes
 .../handlers/__pycache__/scrypt.cpython-312.pyc    |    Bin [31m12972[m -> [32m0[m bytes
 .../__pycache__/sha1_crypt.cpython-312.pyc         |    Bin [31m5929[m -> [32m0[m bytes
 .../__pycache__/sha2_crypt.cpython-312.pyc         |    Bin [31m15358[m -> [32m0[m bytes
 .../__pycache__/sun_md5_crypt.cpython-312.pyc      |    Bin [31m12135[m -> [32m0[m bytes
 .../handlers/__pycache__/windows.cpython-312.pyc   |    Bin [31m11422[m -> [32m0[m bytes
 .../Lib/site-packages/passlib/handlers/argon2.py   |   1009 [31m-[m
 .../Lib/site-packages/passlib/handlers/bcrypt.py   |   1243 [31m-[m
 .../Lib/site-packages/passlib/handlers/cisco.py    |    440 [31m-[m
 .../site-packages/passlib/handlers/des_crypt.py    |    607 [31m-[m
 .../Lib/site-packages/passlib/handlers/digests.py  |    168 [31m-[m
 .../Lib/site-packages/passlib/handlers/django.py   |    512 [31m-[m
 .../Lib/site-packages/passlib/handlers/fshp.py     |    214 [31m-[m
 .../site-packages/passlib/handlers/ldap_digests.py |    359 [31m-[m
 .../site-packages/passlib/handlers/md5_crypt.py    |    346 [31m-[m
 .../Lib/site-packages/passlib/handlers/misc.py     |    269 [31m-[m
 .../Lib/site-packages/passlib/handlers/mssql.py    |    244 [31m-[m
 .../Lib/site-packages/passlib/handlers/mysql.py    |    128 [31m-[m
 .../Lib/site-packages/passlib/handlers/oracle.py   |    172 [31m-[m
 .../Lib/site-packages/passlib/handlers/pbkdf2.py   |    475 [31m-[m
 .../Lib/site-packages/passlib/handlers/phpass.py   |    135 [31m-[m
 .../Lib/site-packages/passlib/handlers/postgres.py |     55 [31m-[m
 .../Lib/site-packages/passlib/handlers/roundup.py  |     29 [31m-[m
 .../Lib/site-packages/passlib/handlers/scram.py    |    582 [31m-[m
 .../Lib/site-packages/passlib/handlers/scrypt.py   |    383 [31m-[m
 .../site-packages/passlib/handlers/sha1_crypt.py   |    158 [31m-[m
 .../site-packages/passlib/handlers/sha2_crypt.py   |    534 [31m-[m
 .../passlib/handlers/sun_md5_crypt.py              |    363 [31m-[m
 .../Lib/site-packages/passlib/handlers/windows.py  |    334 [31m-[m
 backend/venv/Lib/site-packages/passlib/hash.py     |     68 [31m-[m
 backend/venv/Lib/site-packages/passlib/hosts.py    |    106 [31m-[m
 backend/venv/Lib/site-packages/passlib/ifc.py      |    353 [31m-[m
 backend/venv/Lib/site-packages/passlib/pwd.py      |    809 [31m-[m
 backend/venv/Lib/site-packages/passlib/registry.py |    547 [31m-[m
 .../Lib/site-packages/passlib/tests/__init__.py    |      1 [31m-[m
 .../Lib/site-packages/passlib/tests/__main__.py    |      6 [31m-[m
 .../tests/__pycache__/__init__.cpython-312.pyc     |    Bin [31m203[m -> [32m0[m bytes
 .../tests/__pycache__/__main__.cpython-312.pyc     |    Bin [31m357[m -> [32m0[m bytes
 .../__pycache__/_test_bad_register.cpython-312.pyc |    Bin [31m898[m -> [32m0[m bytes
 .../tests/__pycache__/backports.cpython-312.pyc    |    Bin [31m1528[m -> [32m0[m bytes
 .../tests/__pycache__/test_apache.cpython-312.pyc  |    Bin [31m40136[m -> [32m0[m bytes
 .../tests/__pycache__/test_apps.cpython-312.pyc    |    Bin [31m7091[m -> [32m0[m bytes
 .../tests/__pycache__/test_context.cpython-312.pyc |    Bin [31m75696[m -> [32m0[m bytes
 .../test_context_deprecated.cpython-312.pyc        |    Bin [31m31202[m -> [32m0[m bytes
 .../test_crypto_builtin_md4.cpython-312.pyc        |    Bin [31m7005[m -> [32m0[m bytes
 .../__pycache__/test_crypto_des.cpython-312.pyc    |    Bin [31m7284[m -> [32m0[m bytes
 .../__pycache__/test_crypto_digest.cpython-312.pyc |    Bin [31m18878[m -> [32m0[m bytes
 .../__pycache__/test_crypto_scrypt.cpython-312.pyc |    Bin [31m26771[m -> [32m0[m bytes
 .../__pycache__/test_ext_django.cpython-312.pyc    |    Bin [31m37132[m -> [32m0[m bytes
 .../test_ext_django_source.cpython-312.pyc         |    Bin [31m8174[m -> [32m0[m bytes
 .../__pycache__/test_handlers.cpython-312.pyc      |    Bin [31m54151[m -> [32m0[m bytes
 .../test_handlers_argon2.cpython-312.pyc           |    Bin [31m20492[m -> [32m0[m bytes
 .../test_handlers_bcrypt.cpython-312.pyc           |    Bin [31m26052[m -> [32m0[m bytes
 .../test_handlers_cisco.cpython-312.pyc            |    Bin [31m10816[m -> [32m0[m bytes
 .../test_handlers_django.cpython-312.pyc           |    Bin [31m16512[m -> [32m0[m bytes
 .../test_handlers_pbkdf2.cpython-312.pyc           |    Bin [31m18593[m -> [32m0[m bytes
 .../test_handlers_scrypt.cpython-312.pyc           |    Bin [31m3706[m -> [32m0[m bytes
 .../tests/__pycache__/test_hosts.cpython-312.pyc   |    Bin [31m4004[m -> [32m0[m bytes
 .../tests/__pycache__/test_pwd.cpython-312.pyc     |    Bin [31m8314[m -> [32m0[m bytes
 .../__pycache__/test_registry.cpython-312.pyc      |    Bin [31m11217[m -> [32m0[m bytes
 .../tests/__pycache__/test_totp.cpython-312.pyc    |    Bin [31m63639[m -> [32m0[m bytes
 .../tests/__pycache__/test_utils.cpython-312.pyc   |    Bin [31m49392[m -> [32m0[m bytes
 .../test_utils_handlers.cpython-312.pyc            |    Bin [31m43643[m -> [32m0[m bytes
 .../__pycache__/test_utils_md4.cpython-312.pyc     |    Bin [31m1588[m -> [32m0[m bytes
 .../__pycache__/test_utils_pbkdf2.cpython-312.pyc  |    Bin [31m11954[m -> [32m0[m bytes
 .../tests/__pycache__/test_win32.cpython-312.pyc   |    Bin [31m2162[m -> [32m0[m bytes
 .../tests/__pycache__/tox_support.cpython-312.pyc  |    Bin [31m3287[m -> [32m0[m bytes
 .../tests/__pycache__/utils.cpython-312.pyc        |    Bin [31m142163[m -> [32m0[m bytes
 .../passlib/tests/_test_bad_register.py            |     15 [31m-[m
 .../Lib/site-packages/passlib/tests/backports.py   |     67 [31m-[m
 .../Lib/site-packages/passlib/tests/sample1.cfg    |      9 [31m-[m
 .../Lib/site-packages/passlib/tests/sample1b.cfg   |      9 [31m-[m
 .../Lib/site-packages/passlib/tests/sample1c.cfg   |    Bin [31m490[m -> [32m0[m bytes
 .../passlib/tests/sample_config_1s.cfg             |      8 [31m-[m
 .../Lib/site-packages/passlib/tests/test_apache.py |    769 [31m-[m
 .../Lib/site-packages/passlib/tests/test_apps.py   |    139 [31m-[m
 .../site-packages/passlib/tests/test_context.py    |   1786 [31m-[m
 .../passlib/tests/test_context_deprecated.py       |    743 [31m-[m
 .../passlib/tests/test_crypto_builtin_md4.py       |    160 [31m-[m
 .../site-packages/passlib/tests/test_crypto_des.py |    194 [31m-[m
 .../passlib/tests/test_crypto_digest.py            |    544 [31m-[m
 .../passlib/tests/test_crypto_scrypt.py            |    634 [31m-[m
 .../site-packages/passlib/tests/test_ext_django.py |   1080 [31m-[m
 .../passlib/tests/test_ext_django_source.py        |    250 [31m-[m
 .../site-packages/passlib/tests/test_handlers.py   |   1819 [31m-[m
 .../passlib/tests/test_handlers_argon2.py          |    507 [31m-[m
 .../passlib/tests/test_handlers_bcrypt.py          |    688 [31m-[m
 .../passlib/tests/test_handlers_cisco.py           |    457 [31m-[m
 .../passlib/tests/test_handlers_django.py          |    413 [31m-[m
 .../passlib/tests/test_handlers_pbkdf2.py          |    480 [31m-[m
 .../passlib/tests/test_handlers_scrypt.py          |    111 [31m-[m
 .../Lib/site-packages/passlib/tests/test_hosts.py  |     97 [31m-[m
 .../Lib/site-packages/passlib/tests/test_pwd.py    |    205 [31m-[m
 .../site-packages/passlib/tests/test_registry.py   |    228 [31m-[m
 .../Lib/site-packages/passlib/tests/test_totp.py   |   1604 [31m-[m
 .../Lib/site-packages/passlib/tests/test_utils.py  |   1171 [31m-[m
 .../passlib/tests/test_utils_handlers.py           |    870 [31m-[m
 .../site-packages/passlib/tests/test_utils_md4.py  |     41 [31m-[m
 .../passlib/tests/test_utils_pbkdf2.py             |    323 [31m-[m
 .../Lib/site-packages/passlib/tests/test_win32.py  |     50 [31m-[m
 .../Lib/site-packages/passlib/tests/tox_support.py |     83 [31m-[m
 .../venv/Lib/site-packages/passlib/tests/utils.py  |   3621 [31m-[m
 backend/venv/Lib/site-packages/passlib/totp.py     |   1908 [31m-[m
 .../Lib/site-packages/passlib/utils/__init__.py    |   1220 [31m-[m
 .../utils/__pycache__/__init__.cpython-312.pyc     |    Bin [31m38347[m -> [32m0[m bytes
 .../utils/__pycache__/binary.cpython-312.pyc       |    Bin [31m29300[m -> [32m0[m bytes
 .../utils/__pycache__/decor.cpython-312.pyc        |    Bin [31m8747[m -> [32m0[m bytes
 .../passlib/utils/__pycache__/des.cpython-312.pyc  |    Bin [31m1735[m -> [32m0[m bytes
 .../utils/__pycache__/handlers.cpython-312.pyc     |    Bin [31m92228[m -> [32m0[m bytes
 .../passlib/utils/__pycache__/md4.cpython-312.pyc  |    Bin [31m838[m -> [32m0[m bytes
 .../utils/__pycache__/pbkdf2.cpython-312.pyc       |    Bin [31m6294[m -> [32m0[m bytes
 .../venv/Lib/site-packages/passlib/utils/binary.py |    884 [31m-[m
 .../site-packages/passlib/utils/compat/__init__.py |    474 [31m-[m
 .../compat/__pycache__/__init__.cpython-312.pyc    |    Bin [31m14413[m -> [32m0[m bytes
 .../__pycache__/_ordered_dict.cpython-312.pyc      |    Bin [31m10354[m -> [32m0[m bytes
 .../passlib/utils/compat/_ordered_dict.py          |    242 [31m-[m
 .../venv/Lib/site-packages/passlib/utils/decor.py  |    233 [31m-[m
 .../venv/Lib/site-packages/passlib/utils/des.py    |     46 [31m-[m
 .../Lib/site-packages/passlib/utils/handlers.py    |   2711 [31m-[m
 .../venv/Lib/site-packages/passlib/utils/md4.py    |     29 [31m-[m
 .../venv/Lib/site-packages/passlib/utils/pbkdf2.py |    193 [31m-[m
 backend/venv/Lib/site-packages/passlib/win32.py    |     68 [31m-[m
 .../site-packages/pip-25.0.1.dist-info/AUTHORS.txt |    806 [31m-[m
 .../site-packages/pip-25.0.1.dist-info/INSTALLER   |      1 [31m-[m
 .../site-packages/pip-25.0.1.dist-info/LICENSE.txt |     20 [31m-[m
 .../site-packages/pip-25.0.1.dist-info/METADATA    |     90 [31m-[m
 .../Lib/site-packages/pip-25.0.1.dist-info/RECORD  |    854 [31m-[m
 .../site-packages/pip-25.0.1.dist-info/REQUESTED   |      0
 .../Lib/site-packages/pip-25.0.1.dist-info/WHEEL   |      5 [31m-[m
 .../pip-25.0.1.dist-info/entry_points.txt          |      3 [31m-[m
 .../pip-25.0.1.dist-info/top_level.txt             |      1 [31m-[m
 backend/venv/Lib/site-packages/pip/__init__.py     |     13 [31m-[m
 backend/venv/Lib/site-packages/pip/__main__.py     |     24 [31m-[m
 .../venv/Lib/site-packages/pip/__pip-runner__.py   |     50 [31m-[m
 .../pip/__pycache__/__init__.cpython-312.pyc       |    Bin [31m676[m -> [32m0[m bytes
 .../pip/__pycache__/__main__.cpython-312.pyc       |    Bin [31m830[m -> [32m0[m bytes
 .../pip/__pycache__/__pip-runner__.cpython-312.pyc |    Bin [31m2194[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_internal/__init__.py    |     18 [31m-[m
 .../_internal/__pycache__/__init__.cpython-312.pyc |    Bin [31m776[m -> [32m0[m bytes
 .../__pycache__/build_env.cpython-312.pyc          |    Bin [31m14760[m -> [32m0[m bytes
 .../_internal/__pycache__/cache.cpython-312.pyc    |    Bin [31m12656[m -> [32m0[m bytes
 .../__pycache__/configuration.cpython-312.pyc      |    Bin [31m17620[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m36834[m -> [32m0[m bytes
 .../pip/_internal/__pycache__/main.cpython-312.pyc |    Bin [31m659[m -> [32m0[m bytes
 .../__pycache__/pyproject.cpython-312.pyc          |    Bin [31m5107[m -> [32m0[m bytes
 .../self_outdated_check.cpython-312.pyc            |    Bin [31m10392[m -> [32m0[m bytes
 .../__pycache__/wheel_builder.cpython-312.pyc      |    Bin [31m13604[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_internal/build_env.py   |    322 [31m-[m
 .../venv/Lib/site-packages/pip/_internal/cache.py  |    290 [31m-[m
 .../site-packages/pip/_internal/cli/__init__.py    |      4 [31m-[m
 .../cli/__pycache__/__init__.cpython-312.pyc       |    Bin [31m267[m -> [32m0[m bytes
 .../cli/__pycache__/autocompletion.cpython-312.pyc |    Bin [31m8595[m -> [32m0[m bytes
 .../cli/__pycache__/base_command.cpython-312.pyc   |    Bin [31m10497[m -> [32m0[m bytes
 .../cli/__pycache__/cmdoptions.cpython-312.pyc     |    Bin [31m30390[m -> [32m0[m bytes
 .../__pycache__/command_context.cpython-312.pyc    |    Bin [31m1763[m -> [32m0[m bytes
 .../cli/__pycache__/index_command.cpython-312.pyc  |    Bin [31m7170[m -> [32m0[m bytes
 .../_internal/cli/__pycache__/main.cpython-312.pyc |    Bin [31m2289[m -> [32m0[m bytes
 .../cli/__pycache__/main_parser.cpython-312.pyc    |    Bin [31m4895[m -> [32m0[m bytes
 .../cli/__pycache__/parser.cpython-312.pyc         |    Bin [31m15029[m -> [32m0[m bytes
 .../cli/__pycache__/progress_bars.cpython-312.pyc  |    Bin [31m3841[m -> [32m0[m bytes
 .../cli/__pycache__/req_command.cpython-312.pyc    |    Bin [31m12230[m -> [32m0[m bytes
 .../cli/__pycache__/spinners.cpython-312.pyc       |    Bin [31m7822[m -> [32m0[m bytes
 .../cli/__pycache__/status_codes.cpython-312.pyc   |    Bin [31m364[m -> [32m0[m bytes
 .../pip/_internal/cli/autocompletion.py            |    176 [31m-[m
 .../pip/_internal/cli/base_command.py              |    240 [31m-[m
 .../site-packages/pip/_internal/cli/cmdoptions.py  |   1075 [31m-[m
 .../pip/_internal/cli/command_context.py           |     27 [31m-[m
 .../pip/_internal/cli/index_command.py             |    171 [31m-[m
 .../Lib/site-packages/pip/_internal/cli/main.py    |     80 [31m-[m
 .../site-packages/pip/_internal/cli/main_parser.py |    134 [31m-[m
 .../Lib/site-packages/pip/_internal/cli/parser.py  |    294 [31m-[m
 .../pip/_internal/cli/progress_bars.py             |     94 [31m-[m
 .../site-packages/pip/_internal/cli/req_command.py |    329 [31m-[m
 .../site-packages/pip/_internal/cli/spinners.py    |    159 [31m-[m
 .../pip/_internal/cli/status_codes.py              |      6 [31m-[m
 .../pip/_internal/commands/__init__.py             |    132 [31m-[m
 .../commands/__pycache__/__init__.cpython-312.pyc  |    Bin [31m3991[m -> [32m0[m bytes
 .../commands/__pycache__/cache.cpython-312.pyc     |    Bin [31m9917[m -> [32m0[m bytes
 .../commands/__pycache__/check.cpython-312.pyc     |    Bin [31m2581[m -> [32m0[m bytes
 .../__pycache__/completion.cpython-312.pyc         |    Bin [31m5182[m -> [32m0[m bytes
 .../__pycache__/configuration.cpython-312.pyc      |    Bin [31m13152[m -> [32m0[m bytes
 .../commands/__pycache__/debug.cpython-312.pyc     |    Bin [31m10057[m -> [32m0[m bytes
 .../commands/__pycache__/download.cpython-312.pyc  |    Bin [31m7492[m -> [32m0[m bytes
 .../commands/__pycache__/freeze.cpython-312.pyc    |    Bin [31m4374[m -> [32m0[m bytes
 .../commands/__pycache__/hash.cpython-312.pyc      |    Bin [31m2957[m -> [32m0[m bytes
 .../commands/__pycache__/help.cpython-312.pyc      |    Bin [31m1662[m -> [32m0[m bytes
 .../commands/__pycache__/index.cpython-312.pyc     |    Bin [31m6660[m -> [32m0[m bytes
 .../commands/__pycache__/inspect.cpython-312.pyc   |    Bin [31m3969[m -> [32m0[m bytes
 .../commands/__pycache__/install.cpython-312.pyc   |    Bin [31m29081[m -> [32m0[m bytes
 .../commands/__pycache__/list.cpython-312.pyc      |    Bin [31m15746[m -> [32m0[m bytes
 .../commands/__pycache__/search.cpython-312.pyc    |    Bin [31m7507[m -> [32m0[m bytes
 .../commands/__pycache__/show.cpython-312.pyc      |    Bin [31m10926[m -> [32m0[m bytes
 .../commands/__pycache__/uninstall.cpython-312.pyc |    Bin [31m4698[m -> [32m0[m bytes
 .../commands/__pycache__/wheel.cpython-312.pyc     |    Bin [31m8854[m -> [32m0[m bytes
 .../site-packages/pip/_internal/commands/cache.py  |    228 [31m-[m
 .../site-packages/pip/_internal/commands/check.py  |     67 [31m-[m
 .../pip/_internal/commands/completion.py           |    130 [31m-[m
 .../pip/_internal/commands/configuration.py        |    280 [31m-[m
 .../site-packages/pip/_internal/commands/debug.py  |    201 [31m-[m
 .../pip/_internal/commands/download.py             |    146 [31m-[m
 .../site-packages/pip/_internal/commands/freeze.py |    109 [31m-[m
 .../site-packages/pip/_internal/commands/hash.py   |     59 [31m-[m
 .../site-packages/pip/_internal/commands/help.py   |     41 [31m-[m
 .../site-packages/pip/_internal/commands/index.py  |    139 [31m-[m
 .../pip/_internal/commands/inspect.py              |     92 [31m-[m
 .../pip/_internal/commands/install.py              |    784 [31m-[m
 .../site-packages/pip/_internal/commands/list.py   |    375 [31m-[m
 .../site-packages/pip/_internal/commands/search.py |    172 [31m-[m
 .../site-packages/pip/_internal/commands/show.py   |    224 [31m-[m
 .../pip/_internal/commands/uninstall.py            |    114 [31m-[m
 .../site-packages/pip/_internal/commands/wheel.py  |    182 [31m-[m
 .../site-packages/pip/_internal/configuration.py   |    383 [31m-[m
 .../pip/_internal/distributions/__init__.py        |     21 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m930[m -> [32m0[m bytes
 .../distributions/__pycache__/base.cpython-312.pyc |    Bin [31m2882[m -> [32m0[m bytes
 .../__pycache__/installed.cpython-312.pyc          |    Bin [31m1689[m -> [32m0[m bytes
 .../__pycache__/sdist.cpython-312.pyc              |    Bin [31m8416[m -> [32m0[m bytes
 .../__pycache__/wheel.cpython-312.pyc              |    Bin [31m2270[m -> [32m0[m bytes
 .../pip/_internal/distributions/base.py            |     53 [31m-[m
 .../pip/_internal/distributions/installed.py       |     29 [31m-[m
 .../pip/_internal/distributions/sdist.py           |    158 [31m-[m
 .../pip/_internal/distributions/wheel.py           |     42 [31m-[m
 .../Lib/site-packages/pip/_internal/exceptions.py  |    809 [31m-[m
 .../site-packages/pip/_internal/index/__init__.py  |      2 [31m-[m
 .../index/__pycache__/__init__.cpython-312.pyc     |    Bin [31m221[m -> [32m0[m bytes
 .../index/__pycache__/collector.cpython-312.pyc    |    Bin [31m21606[m -> [32m0[m bytes
 .../__pycache__/package_finder.cpython-312.pyc     |    Bin [31m41354[m -> [32m0[m bytes
 .../index/__pycache__/sources.cpython-312.pyc      |    Bin [31m12513[m -> [32m0[m bytes
 .../site-packages/pip/_internal/index/collector.py |    494 [31m-[m
 .../pip/_internal/index/package_finder.py          |   1029 [31m-[m
 .../site-packages/pip/_internal/index/sources.py   |    284 [31m-[m
 .../pip/_internal/locations/__init__.py            |    456 [31m-[m
 .../locations/__pycache__/__init__.cpython-312.pyc |    Bin [31m16429[m -> [32m0[m bytes
 .../__pycache__/_distutils.cpython-312.pyc         |    Bin [31m6780[m -> [32m0[m bytes
 .../__pycache__/_sysconfig.cpython-312.pyc         |    Bin [31m8017[m -> [32m0[m bytes
 .../locations/__pycache__/base.cpython-312.pyc     |    Bin [31m3770[m -> [32m0[m bytes
 .../pip/_internal/locations/_distutils.py          |    172 [31m-[m
 .../pip/_internal/locations/_sysconfig.py          |    214 [31m-[m
 .../site-packages/pip/_internal/locations/base.py  |     81 [31m-[m
 .../venv/Lib/site-packages/pip/_internal/main.py   |     12 [31m-[m
 .../pip/_internal/metadata/__init__.py             |    128 [31m-[m
 .../metadata/__pycache__/__init__.cpython-312.pyc  |    Bin [31m5856[m -> [32m0[m bytes
 .../metadata/__pycache__/_json.cpython-312.pyc     |    Bin [31m2956[m -> [32m0[m bytes
 .../metadata/__pycache__/base.cpython-312.pyc      |    Bin [31m35187[m -> [32m0[m bytes
 .../__pycache__/pkg_resources.cpython-312.pyc      |    Bin [31m16073[m -> [32m0[m bytes
 .../site-packages/pip/_internal/metadata/_json.py  |     86 [31m-[m
 .../site-packages/pip/_internal/metadata/base.py   |    688 [31m-[m
 .../pip/_internal/metadata/importlib/__init__.py   |      6 [31m-[m
 .../importlib/__pycache__/__init__.cpython-312.pyc |    Bin [31m347[m -> [32m0[m bytes
 .../importlib/__pycache__/_compat.cpython-312.pyc  |    Bin [31m4480[m -> [32m0[m bytes
 .../importlib/__pycache__/_dists.cpython-312.pyc   |    Bin [31m12868[m -> [32m0[m bytes
 .../importlib/__pycache__/_envs.cpython-312.pyc    |    Bin [31m11068[m -> [32m0[m bytes
 .../pip/_internal/metadata/importlib/_compat.py    |     85 [31m-[m
 .../pip/_internal/metadata/importlib/_dists.py     |    228 [31m-[m
 .../pip/_internal/metadata/importlib/_envs.py      |    189 [31m-[m
 .../pip/_internal/metadata/pkg_resources.py        |    301 [31m-[m
 .../site-packages/pip/_internal/models/__init__.py |      2 [31m-[m
 .../models/__pycache__/__init__.cpython-312.pyc    |    Bin [31m255[m -> [32m0[m bytes
 .../models/__pycache__/candidate.cpython-312.pyc   |    Bin [31m1593[m -> [32m0[m bytes
 .../models/__pycache__/direct_url.cpython-312.pyc  |    Bin [31m10833[m -> [32m0[m bytes
 .../__pycache__/format_control.cpython-312.pyc     |    Bin [31m4212[m -> [32m0[m bytes
 .../models/__pycache__/index.cpython-312.pyc       |    Bin [31m1683[m -> [32m0[m bytes
 .../installation_report.cpython-312.pyc            |    Bin [31m2266[m -> [32m0[m bytes
 .../models/__pycache__/link.cpython-312.pyc        |    Bin [31m26972[m -> [32m0[m bytes
 .../models/__pycache__/scheme.cpython-312.pyc      |    Bin [31m1012[m -> [32m0[m bytes
 .../__pycache__/search_scope.cpython-312.pyc       |    Bin [31m4976[m -> [32m0[m bytes
 .../__pycache__/selection_prefs.cpython-312.pyc    |    Bin [31m1840[m -> [32m0[m bytes
 .../__pycache__/target_python.cpython-312.pyc      |    Bin [31m4942[m -> [32m0[m bytes
 .../models/__pycache__/wheel.cpython-312.pyc       |    Bin [31m6541[m -> [32m0[m bytes
 .../pip/_internal/models/candidate.py              |     25 [31m-[m
 .../pip/_internal/models/direct_url.py             |    224 [31m-[m
 .../pip/_internal/models/format_control.py         |     78 [31m-[m
 .../site-packages/pip/_internal/models/index.py    |     28 [31m-[m
 .../pip/_internal/models/installation_report.py    |     56 [31m-[m
 .../Lib/site-packages/pip/_internal/models/link.py |    604 [31m-[m
 .../site-packages/pip/_internal/models/scheme.py   |     25 [31m-[m
 .../pip/_internal/models/search_scope.py           |    127 [31m-[m
 .../pip/_internal/models/selection_prefs.py        |     53 [31m-[m
 .../pip/_internal/models/target_python.py          |    121 [31m-[m
 .../site-packages/pip/_internal/models/wheel.py    |    118 [31m-[m
 .../pip/_internal/network/__init__.py              |      2 [31m-[m
 .../network/__pycache__/__init__.cpython-312.pyc   |    Bin [31m243[m -> [32m0[m bytes
 .../network/__pycache__/auth.cpython-312.pyc       |    Bin [31m22088[m -> [32m0[m bytes
 .../network/__pycache__/cache.cpython-312.pyc      |    Bin [31m7035[m -> [32m0[m bytes
 .../network/__pycache__/download.cpython-312.pyc   |    Bin [31m8468[m -> [32m0[m bytes
 .../network/__pycache__/lazy_wheel.cpython-312.pyc |    Bin [31m11596[m -> [32m0[m bytes
 .../network/__pycache__/session.cpython-312.pyc    |    Bin [31m18895[m -> [32m0[m bytes
 .../network/__pycache__/utils.cpython-312.pyc      |    Bin [31m2244[m -> [32m0[m bytes
 .../network/__pycache__/xmlrpc.cpython-312.pyc     |    Bin [31m2938[m -> [32m0[m bytes
 .../site-packages/pip/_internal/network/auth.py    |    566 [31m-[m
 .../site-packages/pip/_internal/network/cache.py   |    118 [31m-[m
 .../pip/_internal/network/download.py              |    187 [31m-[m
 .../pip/_internal/network/lazy_wheel.py            |    210 [31m-[m
 .../site-packages/pip/_internal/network/session.py |    523 [31m-[m
 .../site-packages/pip/_internal/network/utils.py   |     98 [31m-[m
 .../site-packages/pip/_internal/network/xmlrpc.py  |     62 [31m-[m
 .../pip/_internal/operations/__init__.py           |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m186[m -> [32m0[m bytes
 .../operations/__pycache__/check.cpython-312.pyc   |    Bin [31m7093[m -> [32m0[m bytes
 .../operations/__pycache__/freeze.cpython-312.pyc  |    Bin [31m10237[m -> [32m0[m bytes
 .../operations/__pycache__/prepare.cpython-312.pyc |    Bin [31m25761[m -> [32m0[m bytes
 .../pip/_internal/operations/build/__init__.py     |      0
 .../build/__pycache__/__init__.cpython-312.pyc     |    Bin [31m192[m -> [32m0[m bytes
 .../__pycache__/build_tracker.cpython-312.pyc      |    Bin [31m7656[m -> [32m0[m bytes
 .../build/__pycache__/metadata.cpython-312.pyc     |    Bin [31m1846[m -> [32m0[m bytes
 .../__pycache__/metadata_editable.cpython-312.pyc  |    Bin [31m1900[m -> [32m0[m bytes
 .../__pycache__/metadata_legacy.cpython-312.pyc    |    Bin [31m3000[m -> [32m0[m bytes
 .../build/__pycache__/wheel.cpython-312.pyc        |    Bin [31m1666[m -> [32m0[m bytes
 .../__pycache__/wheel_editable.cpython-312.pyc     |    Bin [31m2005[m -> [32m0[m bytes
 .../build/__pycache__/wheel_legacy.cpython-312.pyc |    Bin [31m3835[m -> [32m0[m bytes
 .../_internal/operations/build/build_tracker.py    |    138 [31m-[m
 .../pip/_internal/operations/build/metadata.py     |     39 [31m-[m
 .../operations/build/metadata_editable.py          |     42 [31m-[m
 .../_internal/operations/build/metadata_legacy.py  |     74 [31m-[m
 .../pip/_internal/operations/build/wheel.py        |     37 [31m-[m
 .../_internal/operations/build/wheel_editable.py   |     46 [31m-[m
 .../pip/_internal/operations/build/wheel_legacy.py |    102 [31m-[m
 .../pip/_internal/operations/check.py              |    181 [31m-[m
 .../pip/_internal/operations/freeze.py             |    256 [31m-[m
 .../pip/_internal/operations/install/__init__.py   |      2 [31m-[m
 .../install/__pycache__/__init__.cpython-312.pyc   |    Bin [31m255[m -> [32m0[m bytes
 .../__pycache__/editable_legacy.cpython-312.pyc    |    Bin [31m1787[m -> [32m0[m bytes
 .../install/__pycache__/wheel.cpython-312.pyc      |    Bin [31m34092[m -> [32m0[m bytes
 .../operations/install/editable_legacy.py          |     47 [31m-[m
 .../pip/_internal/operations/install/wheel.py      |    741 [31m-[m
 .../pip/_internal/operations/prepare.py            |    732 [31m-[m
 .../Lib/site-packages/pip/_internal/pyproject.py   |    185 [31m-[m
 .../site-packages/pip/_internal/req/__init__.py    |     90 [31m-[m
 .../req/__pycache__/__init__.cpython-312.pyc       |    Bin [31m3434[m -> [32m0[m bytes
 .../req/__pycache__/constructors.cpython-312.pyc   |    Bin [31m21244[m -> [32m0[m bytes
 .../req/__pycache__/req_file.cpython-312.pyc       |    Bin [31m24227[m -> [32m0[m bytes
 .../req/__pycache__/req_install.cpython-312.pyc    |    Bin [31m38459[m -> [32m0[m bytes
 .../req/__pycache__/req_set.cpython-312.pyc        |    Bin [31m5472[m -> [32m0[m bytes
 .../req/__pycache__/req_uninstall.cpython-312.pyc  |    Bin [31m32083[m -> [32m0[m bytes
 .../pip/_internal/req/constructors.py              |    560 [31m-[m
 .../site-packages/pip/_internal/req/req_file.py    |    623 [31m-[m
 .../site-packages/pip/_internal/req/req_install.py |    934 [31m-[m
 .../Lib/site-packages/pip/_internal/req/req_set.py |     82 [31m-[m
 .../pip/_internal/req/req_uninstall.py             |    633 [31m-[m
 .../pip/_internal/resolution/__init__.py           |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m186[m -> [32m0[m bytes
 .../resolution/__pycache__/base.cpython-312.pyc    |    Bin [31m1174[m -> [32m0[m bytes
 .../site-packages/pip/_internal/resolution/base.py |     20 [31m-[m
 .../pip/_internal/resolution/legacy/__init__.py    |      0
 .../legacy/__pycache__/__init__.cpython-312.pyc    |    Bin [31m193[m -> [32m0[m bytes
 .../legacy/__pycache__/resolver.cpython-312.pyc    |    Bin [31m22568[m -> [32m0[m bytes
 .../pip/_internal/resolution/legacy/resolver.py    |    597 [31m-[m
 .../_internal/resolution/resolvelib/__init__.py    |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m197[m -> [32m0[m bytes
 .../resolvelib/__pycache__/base.cpython-312.pyc    |    Bin [31m8138[m -> [32m0[m bytes
 .../__pycache__/candidates.cpython-312.pyc         |    Bin [31m29397[m -> [32m0[m bytes
 .../resolvelib/__pycache__/factory.cpython-312.pyc |    Bin [31m32475[m -> [32m0[m bytes
 .../__pycache__/found_candidates.cpython-312.pyc   |    Bin [31m6782[m -> [32m0[m bytes
 .../__pycache__/provider.cpython-312.pyc           |    Bin [31m10512[m -> [32m0[m bytes
 .../__pycache__/reporter.cpython-312.pyc           |    Bin [31m5029[m -> [32m0[m bytes
 .../__pycache__/requirements.cpython-312.pyc       |    Bin [31m15345[m -> [32m0[m bytes
 .../__pycache__/resolver.cpython-312.pyc           |    Bin [31m12303[m -> [32m0[m bytes
 .../pip/_internal/resolution/resolvelib/base.py    |    139 [31m-[m
 .../_internal/resolution/resolvelib/candidates.py  |    574 [31m-[m
 .../pip/_internal/resolution/resolvelib/factory.py |    823 [31m-[m
 .../resolution/resolvelib/found_candidates.py      |    174 [31m-[m
 .../_internal/resolution/resolvelib/provider.py    |    258 [31m-[m
 .../_internal/resolution/resolvelib/reporter.py    |     81 [31m-[m
 .../resolution/resolvelib/requirements.py          |    245 [31m-[m
 .../_internal/resolution/resolvelib/resolver.py    |    317 [31m-[m
 .../pip/_internal/self_outdated_check.py           |    252 [31m-[m
 .../site-packages/pip/_internal/utils/__init__.py  |      0
 .../utils/__pycache__/__init__.cpython-312.pyc     |    Bin [31m181[m -> [32m0[m bytes
 .../utils/__pycache__/_jaraco_text.cpython-312.pyc |    Bin [31m4516[m -> [32m0[m bytes
 .../utils/__pycache__/_log.cpython-312.pyc         |    Bin [31m1852[m -> [32m0[m bytes
 .../utils/__pycache__/appdirs.cpython-312.pyc      |    Bin [31m2396[m -> [32m0[m bytes
 .../utils/__pycache__/compat.cpython-312.pyc       |    Bin [31m2893[m -> [32m0[m bytes
 .../__pycache__/compatibility_tags.cpython-312.pyc |    Bin [31m6336[m -> [32m0[m bytes
 .../utils/__pycache__/datetime.cpython-312.pyc     |    Bin [31m670[m -> [32m0[m bytes
 .../utils/__pycache__/deprecation.cpython-312.pyc  |    Bin [31m4177[m -> [32m0[m bytes
 .../__pycache__/direct_url_helpers.cpython-312.pyc |    Bin [31m3522[m -> [32m0[m bytes
 .../utils/__pycache__/egg_link.cpython-312.pyc     |    Bin [31m3192[m -> [32m0[m bytes
 .../utils/__pycache__/entrypoints.cpython-312.pyc  |    Bin [31m3979[m -> [32m0[m bytes
 .../utils/__pycache__/filesystem.cpython-312.pyc   |    Bin [31m7315[m -> [32m0[m bytes
 .../utils/__pycache__/filetypes.cpython-312.pyc    |    Bin [31m1150[m -> [32m0[m bytes
 .../utils/__pycache__/glibc.cpython-312.pyc        |    Bin [31m2405[m -> [32m0[m bytes
 .../utils/__pycache__/hashes.cpython-312.pyc       |    Bin [31m7589[m -> [32m0[m bytes
 .../utils/__pycache__/logging.cpython-312.pyc      |    Bin [31m13877[m -> [32m0[m bytes
 .../utils/__pycache__/misc.cpython-312.pyc         |    Bin [31m33212[m -> [32m0[m bytes
 .../utils/__pycache__/packaging.cpython-312.pyc    |    Bin [31m2646[m -> [32m0[m bytes
 .../utils/__pycache__/retry.cpython-312.pyc        |    Bin [31m2094[m -> [32m0[m bytes
 .../__pycache__/setuptools_build.cpython-312.pyc   |    Bin [31m4536[m -> [32m0[m bytes
 .../utils/__pycache__/subprocess.cpython-312.pyc   |    Bin [31m8625[m -> [32m0[m bytes
 .../utils/__pycache__/temp_dir.cpython-312.pyc     |    Bin [31m12010[m -> [32m0[m bytes
 .../utils/__pycache__/unpacking.cpython-312.pyc    |    Bin [31m13484[m -> [32m0[m bytes
 .../utils/__pycache__/urls.cpython-312.pyc         |    Bin [31m2063[m -> [32m0[m bytes
 .../utils/__pycache__/virtualenv.cpython-312.pyc   |    Bin [31m4452[m -> [32m0[m bytes
 .../utils/__pycache__/wheel.cpython-312.pyc        |    Bin [31m5889[m -> [32m0[m bytes
 .../pip/_internal/utils/_jaraco_text.py            |    109 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/_log.py  |     38 [31m-[m
 .../site-packages/pip/_internal/utils/appdirs.py   |     52 [31m-[m
 .../site-packages/pip/_internal/utils/compat.py    |     79 [31m-[m
 .../pip/_internal/utils/compatibility_tags.py      |    188 [31m-[m
 .../site-packages/pip/_internal/utils/datetime.py  |     11 [31m-[m
 .../pip/_internal/utils/deprecation.py             |    124 [31m-[m
 .../pip/_internal/utils/direct_url_helpers.py      |     87 [31m-[m
 .../site-packages/pip/_internal/utils/egg_link.py  |     80 [31m-[m
 .../pip/_internal/utils/entrypoints.py             |     84 [31m-[m
 .../pip/_internal/utils/filesystem.py              |    149 [31m-[m
 .../site-packages/pip/_internal/utils/filetypes.py |     27 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/glibc.py |    101 [31m-[m
 .../site-packages/pip/_internal/utils/hashes.py    |    147 [31m-[m
 .../site-packages/pip/_internal/utils/logging.py   |    354 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/misc.py  |    773 [31m-[m
 .../site-packages/pip/_internal/utils/packaging.py |     58 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/retry.py |     42 [31m-[m
 .../pip/_internal/utils/setuptools_build.py        |    146 [31m-[m
 .../pip/_internal/utils/subprocess.py              |    245 [31m-[m
 .../site-packages/pip/_internal/utils/temp_dir.py  |    296 [31m-[m
 .../site-packages/pip/_internal/utils/unpacking.py |    337 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/urls.py  |     55 [31m-[m
 .../pip/_internal/utils/virtualenv.py              |    104 [31m-[m
 .../Lib/site-packages/pip/_internal/utils/wheel.py |    134 [31m-[m
 .../site-packages/pip/_internal/vcs/__init__.py    |     15 [31m-[m
 .../vcs/__pycache__/__init__.cpython-312.pyc       |    Bin [31m520[m -> [32m0[m bytes
 .../vcs/__pycache__/bazaar.cpython-312.pyc         |    Bin [31m5041[m -> [32m0[m bytes
 .../_internal/vcs/__pycache__/git.cpython-312.pyc  |    Bin [31m19006[m -> [32m0[m bytes
 .../vcs/__pycache__/mercurial.cpython-312.pyc      |    Bin [31m7594[m -> [32m0[m bytes
 .../vcs/__pycache__/subversion.cpython-312.pyc     |    Bin [31m12513[m -> [32m0[m bytes
 .../vcs/__pycache__/versioncontrol.cpython-312.pyc |    Bin [31m28986[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_internal/vcs/bazaar.py  |    112 [31m-[m
 .../Lib/site-packages/pip/_internal/vcs/git.py     |    527 [31m-[m
 .../site-packages/pip/_internal/vcs/mercurial.py   |    163 [31m-[m
 .../site-packages/pip/_internal/vcs/subversion.py  |    324 [31m-[m
 .../pip/_internal/vcs/versioncontrol.py            |    688 [31m-[m
 .../site-packages/pip/_internal/wheel_builder.py   |    354 [31m-[m
 .../venv/Lib/site-packages/pip/_vendor/__init__.py |    116 [31m-[m
 .../_vendor/__pycache__/__init__.cpython-312.pyc   |    Bin [31m4539[m -> [32m0[m bytes
 .../__pycache__/typing_extensions.cpython-312.pyc  |    Bin [31m139441[m -> [32m0[m bytes
 .../pip/_vendor/cachecontrol/__init__.py           |     29 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m892[m -> [32m0[m bytes
 .../cachecontrol/__pycache__/_cmd.cpython-312.pyc  |    Bin [31m2636[m -> [32m0[m bytes
 .../__pycache__/adapter.cpython-312.pyc            |    Bin [31m6454[m -> [32m0[m bytes
 .../cachecontrol/__pycache__/cache.cpython-312.pyc |    Bin [31m3777[m -> [32m0[m bytes
 .../__pycache__/controller.cpython-312.pyc         |    Bin [31m16214[m -> [32m0[m bytes
 .../__pycache__/filewrapper.cpython-312.pyc        |    Bin [31m4337[m -> [32m0[m bytes
 .../__pycache__/heuristics.cpython-312.pyc         |    Bin [31m6687[m -> [32m0[m bytes
 .../__pycache__/serialize.cpython-312.pyc          |    Bin [31m5251[m -> [32m0[m bytes
 .../__pycache__/wrapper.cpython-312.pyc            |    Bin [31m1664[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/cachecontrol/_cmd.py |     70 [31m-[m
 .../pip/_vendor/cachecontrol/adapter.py            |    161 [31m-[m
 .../pip/_vendor/cachecontrol/cache.py              |     75 [31m-[m
 .../pip/_vendor/cachecontrol/caches/__init__.py    |      8 [31m-[m
 .../caches/__pycache__/__init__.cpython-312.pyc    |    Bin [31m425[m -> [32m0[m bytes
 .../caches/__pycache__/file_cache.cpython-312.pyc  |    Bin [31m7734[m -> [32m0[m bytes
 .../caches/__pycache__/redis_cache.cpython-312.pyc |    Bin [31m2723[m -> [32m0[m bytes
 .../pip/_vendor/cachecontrol/caches/file_cache.py  |    182 [31m-[m
 .../pip/_vendor/cachecontrol/caches/redis_cache.py |     48 [31m-[m
 .../pip/_vendor/cachecontrol/controller.py         |    500 [31m-[m
 .../pip/_vendor/cachecontrol/filewrapper.py        |    119 [31m-[m
 .../pip/_vendor/cachecontrol/heuristics.py         |    157 [31m-[m
 .../pip/_vendor/cachecontrol/py.typed              |      0
 .../pip/_vendor/cachecontrol/serialize.py          |    146 [31m-[m
 .../pip/_vendor/cachecontrol/wrapper.py            |     43 [31m-[m
 .../site-packages/pip/_vendor/certifi/__init__.py  |      4 [31m-[m
 .../site-packages/pip/_vendor/certifi/__main__.py  |     12 [31m-[m
 .../certifi/__pycache__/__init__.cpython-312.pyc   |    Bin [31m308[m -> [32m0[m bytes
 .../certifi/__pycache__/__main__.cpython-312.pyc   |    Bin [31m635[m -> [32m0[m bytes
 .../certifi/__pycache__/core.cpython-312.pyc       |    Bin [31m3201[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/certifi/cacert.pem   |   4929 [31m-[m
 .../Lib/site-packages/pip/_vendor/certifi/core.py  |    114 [31m-[m
 .../Lib/site-packages/pip/_vendor/certifi/py.typed |      0
 .../site-packages/pip/_vendor/distlib/__init__.py  |     33 [31m-[m
 .../distlib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1259[m -> [32m0[m bytes
 .../distlib/__pycache__/compat.cpython-312.pyc     |    Bin [31m45516[m -> [32m0[m bytes
 .../distlib/__pycache__/database.cpython-312.pyc   |    Bin [31m65571[m -> [32m0[m bytes
 .../distlib/__pycache__/index.cpython-312.pyc      |    Bin [31m24306[m -> [32m0[m bytes
 .../distlib/__pycache__/locators.cpython-312.pyc   |    Bin [31m59851[m -> [32m0[m bytes
 .../distlib/__pycache__/manifest.cpython-312.pyc   |    Bin [31m15066[m -> [32m0[m bytes
 .../distlib/__pycache__/markers.cpython-312.pyc    |    Bin [31m7644[m -> [32m0[m bytes
 .../distlib/__pycache__/metadata.cpython-312.pyc   |    Bin [31m41550[m -> [32m0[m bytes
 .../distlib/__pycache__/resources.cpython-312.pyc  |    Bin [31m17302[m -> [32m0[m bytes
 .../distlib/__pycache__/scripts.cpython-312.pyc    |    Bin [31m19743[m -> [32m0[m bytes
 .../distlib/__pycache__/util.cpython-312.pyc       |    Bin [31m88025[m -> [32m0[m bytes
 .../distlib/__pycache__/version.cpython-312.pyc    |    Bin [31m30334[m -> [32m0[m bytes
 .../distlib/__pycache__/wheel.cpython-312.pyc      |    Bin [31m52535[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/distlib/compat.py    |   1137 [31m-[m
 .../site-packages/pip/_vendor/distlib/database.py  |   1329 [31m-[m
 .../Lib/site-packages/pip/_vendor/distlib/index.py |    508 [31m-[m
 .../site-packages/pip/_vendor/distlib/locators.py  |   1295 [31m-[m
 .../site-packages/pip/_vendor/distlib/manifest.py  |    384 [31m-[m
 .../site-packages/pip/_vendor/distlib/markers.py   |    162 [31m-[m
 .../site-packages/pip/_vendor/distlib/metadata.py  |   1031 [31m-[m
 .../site-packages/pip/_vendor/distlib/resources.py |    358 [31m-[m
 .../site-packages/pip/_vendor/distlib/scripts.py   |    447 [31m-[m
 .../Lib/site-packages/pip/_vendor/distlib/t32.exe  |    Bin [31m97792[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/distlib/t64-arm.exe  |    Bin [31m182784[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/distlib/t64.exe  |    Bin [31m108032[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/distlib/util.py  |   1984 [31m-[m
 .../site-packages/pip/_vendor/distlib/version.py   |    750 [31m-[m
 .../Lib/site-packages/pip/_vendor/distlib/w32.exe  |    Bin [31m91648[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/distlib/w64-arm.exe  |    Bin [31m168448[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/distlib/w64.exe  |    Bin [31m101888[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/distlib/wheel.py |   1100 [31m-[m
 .../site-packages/pip/_vendor/distro/__init__.py   |     54 [31m-[m
 .../site-packages/pip/_vendor/distro/__main__.py   |      4 [31m-[m
 .../distro/__pycache__/__init__.cpython-312.pyc    |    Bin [31m950[m -> [32m0[m bytes
 .../distro/__pycache__/__main__.cpython-312.pyc    |    Bin [31m282[m -> [32m0[m bytes
 .../distro/__pycache__/distro.cpython-312.pyc      |    Bin [31m53782[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/distro/distro.py |   1403 [31m-[m
 .../Lib/site-packages/pip/_vendor/distro/py.typed  |      0
 .../Lib/site-packages/pip/_vendor/idna/__init__.py |     45 [31m-[m
 .../idna/__pycache__/__init__.cpython-312.pyc      |    Bin [31m876[m -> [32m0[m bytes
 .../_vendor/idna/__pycache__/codec.cpython-312.pyc |    Bin [31m4966[m -> [32m0[m bytes
 .../idna/__pycache__/compat.cpython-312.pyc        |    Bin [31m880[m -> [32m0[m bytes
 .../_vendor/idna/__pycache__/core.cpython-312.pyc  |    Bin [31m16111[m -> [32m0[m bytes
 .../idna/__pycache__/idnadata.cpython-312.pyc      |    Bin [31m99466[m -> [32m0[m bytes
 .../idna/__pycache__/intranges.cpython-312.pyc     |    Bin [31m2623[m -> [32m0[m bytes
 .../idna/__pycache__/package_data.cpython-312.pyc  |    Bin [31m207[m -> [32m0[m bytes
 .../idna/__pycache__/uts46data.cpython-312.pyc     |    Bin [31m158836[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/idna/codec.py    |    122 [31m-[m
 .../Lib/site-packages/pip/_vendor/idna/compat.py   |     15 [31m-[m
 .../Lib/site-packages/pip/_vendor/idna/core.py     |    437 [31m-[m
 .../Lib/site-packages/pip/_vendor/idna/idnadata.py |   4243 [31m-[m
 .../site-packages/pip/_vendor/idna/intranges.py    |     57 [31m-[m
 .../site-packages/pip/_vendor/idna/package_data.py |      1 [31m-[m
 .../Lib/site-packages/pip/_vendor/idna/py.typed    |      0
 .../site-packages/pip/_vendor/idna/uts46data.py    |   8681 [31m--[m
 .../site-packages/pip/_vendor/msgpack/__init__.py  |     55 [31m-[m
 .../msgpack/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1729[m -> [32m0[m bytes
 .../msgpack/__pycache__/exceptions.cpython-312.pyc |    Bin [31m2015[m -> [32m0[m bytes
 .../msgpack/__pycache__/ext.cpython-312.pyc        |    Bin [31m8283[m -> [32m0[m bytes
 .../msgpack/__pycache__/fallback.cpython-312.pyc   |    Bin [31m41480[m -> [32m0[m bytes
 .../pip/_vendor/msgpack/exceptions.py              |     48 [31m-[m
 .../Lib/site-packages/pip/_vendor/msgpack/ext.py   |    170 [31m-[m
 .../site-packages/pip/_vendor/msgpack/fallback.py  |    929 [31m-[m
 .../pip/_vendor/packaging/__init__.py              |     15 [31m-[m
 .../packaging/__pycache__/__init__.cpython-312.pyc |    Bin [31m548[m -> [32m0[m bytes
 .../packaging/__pycache__/_elffile.cpython-312.pyc |    Bin [31m5013[m -> [32m0[m bytes
 .../__pycache__/_manylinux.cpython-312.pyc         |    Bin [31m9701[m -> [32m0[m bytes
 .../__pycache__/_musllinux.cpython-312.pyc         |    Bin [31m4544[m -> [32m0[m bytes
 .../packaging/__pycache__/_parser.cpython-312.pyc  |    Bin [31m13975[m -> [32m0[m bytes
 .../__pycache__/_structures.cpython-312.pyc        |    Bin [31m3231[m -> [32m0[m bytes
 .../__pycache__/_tokenizer.cpython-312.pyc         |    Bin [31m7905[m -> [32m0[m bytes
 .../packaging/__pycache__/markers.cpython-312.pyc  |    Bin [31m11364[m -> [32m0[m bytes
 .../packaging/__pycache__/metadata.cpython-312.pyc |    Bin [31m27202[m -> [32m0[m bytes
 .../__pycache__/requirements.cpython-312.pyc       |    Bin [31m4400[m -> [32m0[m bytes
 .../__pycache__/specifiers.cpython-312.pyc         |    Bin [31m39032[m -> [32m0[m bytes
 .../packaging/__pycache__/tags.cpython-312.pyc     |    Bin [31m22995[m -> [32m0[m bytes
 .../packaging/__pycache__/utils.cpython-312.pyc    |    Bin [31m6625[m -> [32m0[m bytes
 .../packaging/__pycache__/version.cpython-312.pyc  |    Bin [31m20476[m -> [32m0[m bytes
 .../pip/_vendor/packaging/_elffile.py              |    110 [31m-[m
 .../pip/_vendor/packaging/_manylinux.py            |    263 [31m-[m
 .../pip/_vendor/packaging/_musllinux.py            |     85 [31m-[m
 .../site-packages/pip/_vendor/packaging/_parser.py |    354 [31m-[m
 .../pip/_vendor/packaging/_structures.py           |     61 [31m-[m
 .../pip/_vendor/packaging/_tokenizer.py            |    194 [31m-[m
 .../pip/_vendor/packaging/licenses/__init__.py     |    145 [31m-[m
 .../licenses/__pycache__/__init__.cpython-312.pyc  |    Bin [31m4110[m -> [32m0[m bytes
 .../licenses/__pycache__/_spdx.cpython-312.pyc     |    Bin [31m47354[m -> [32m0[m bytes
 .../pip/_vendor/packaging/licenses/_spdx.py        |    759 [31m-[m
 .../site-packages/pip/_vendor/packaging/markers.py |    331 [31m-[m
 .../pip/_vendor/packaging/metadata.py              |    863 [31m-[m
 .../site-packages/pip/_vendor/packaging/py.typed   |      0
 .../pip/_vendor/packaging/requirements.py          |     91 [31m-[m
 .../pip/_vendor/packaging/specifiers.py            |   1020 [31m-[m
 .../site-packages/pip/_vendor/packaging/tags.py    |    617 [31m-[m
 .../site-packages/pip/_vendor/packaging/utils.py   |    163 [31m-[m
 .../site-packages/pip/_vendor/packaging/version.py |    582 [31m-[m
 .../pip/_vendor/pkg_resources/__init__.py          |   3676 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m161251[m -> [32m0[m bytes
 .../pip/_vendor/platformdirs/__init__.py           |    631 [31m-[m
 .../pip/_vendor/platformdirs/__main__.py           |     55 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m19837[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m1938[m -> [32m0[m bytes
 .../__pycache__/android.cpython-312.pyc            |    Bin [31m10687[m -> [32m0[m bytes
 .../platformdirs/__pycache__/api.cpython-312.pyc   |    Bin [31m13294[m -> [32m0[m bytes
 .../platformdirs/__pycache__/macos.cpython-312.pyc |    Bin [31m8814[m -> [32m0[m bytes
 .../platformdirs/__pycache__/unix.cpython-312.pyc  |    Bin [31m14680[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m587[m -> [32m0[m bytes
 .../__pycache__/windows.cpython-312.pyc            |    Bin [31m13664[m -> [32m0[m bytes
 .../pip/_vendor/platformdirs/android.py            |    249 [31m-[m
 .../site-packages/pip/_vendor/platformdirs/api.py  |    298 [31m-[m
 .../pip/_vendor/platformdirs/macos.py              |    144 [31m-[m
 .../pip/_vendor/platformdirs/py.typed              |      0
 .../site-packages/pip/_vendor/platformdirs/unix.py |    269 [31m-[m
 .../pip/_vendor/platformdirs/version.py            |     16 [31m-[m
 .../pip/_vendor/platformdirs/windows.py            |    272 [31m-[m
 .../site-packages/pip/_vendor/pygments/__init__.py |     82 [31m-[m
 .../site-packages/pip/_vendor/pygments/__main__.py |     17 [31m-[m
 .../pygments/__pycache__/__init__.cpython-312.pyc  |    Bin [31m3479[m -> [32m0[m bytes
 .../pygments/__pycache__/__main__.cpython-312.pyc  |    Bin [31m725[m -> [32m0[m bytes
 .../pygments/__pycache__/cmdline.cpython-312.pyc   |    Bin [31m26575[m -> [32m0[m bytes
 .../pygments/__pycache__/console.cpython-312.pyc   |    Bin [31m2619[m -> [32m0[m bytes
 .../pygments/__pycache__/filter.cpython-312.pyc    |    Bin [31m3212[m -> [32m0[m bytes
 .../pygments/__pycache__/formatter.cpython-312.pyc |    Bin [31m4711[m -> [32m0[m bytes
 .../pygments/__pycache__/lexer.cpython-312.pyc     |    Bin [31m38352[m -> [32m0[m bytes
 .../pygments/__pycache__/modeline.cpython-312.pyc  |    Bin [31m1550[m -> [32m0[m bytes
 .../pygments/__pycache__/plugin.cpython-312.pyc    |    Bin [31m2599[m -> [32m0[m bytes
 .../pygments/__pycache__/regexopt.cpython-312.pyc  |    Bin [31m4068[m -> [32m0[m bytes
 .../pygments/__pycache__/scanner.cpython-312.pyc   |    Bin [31m4747[m -> [32m0[m bytes
 .../pygments/__pycache__/sphinxext.cpython-312.pyc |    Bin [31m12089[m -> [32m0[m bytes
 .../pygments/__pycache__/style.cpython-312.pyc     |    Bin [31m6684[m -> [32m0[m bytes
 .../pygments/__pycache__/token.cpython-312.pyc     |    Bin [31m8180[m -> [32m0[m bytes
 .../pygments/__pycache__/unistring.cpython-312.pyc |    Bin [31m32963[m -> [32m0[m bytes
 .../pygments/__pycache__/util.cpython-312.pyc      |    Bin [31m14060[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/pygments/cmdline.py  |    668 [31m-[m
 .../site-packages/pip/_vendor/pygments/console.py  |     70 [31m-[m
 .../site-packages/pip/_vendor/pygments/filter.py   |     70 [31m-[m
 .../pip/_vendor/pygments/filters/__init__.py       |    940 [31m-[m
 .../filters/__pycache__/__init__.cpython-312.pyc   |    Bin [31m37902[m -> [32m0[m bytes
 .../pip/_vendor/pygments/formatter.py              |    129 [31m-[m
 .../pip/_vendor/pygments/formatters/__init__.py    |    157 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m6893[m -> [32m0[m bytes
 .../__pycache__/_mapping.cpython-312.pyc           |    Bin [31m4206[m -> [32m0[m bytes
 .../formatters/__pycache__/bbcode.cpython-312.pyc  |    Bin [31m4213[m -> [32m0[m bytes
 .../formatters/__pycache__/groff.cpython-312.pyc   |    Bin [31m7284[m -> [32m0[m bytes
 .../formatters/__pycache__/html.cpython-312.pyc    |    Bin [31m41017[m -> [32m0[m bytes
 .../formatters/__pycache__/img.cpython-312.pyc     |    Bin [31m28539[m -> [32m0[m bytes
 .../formatters/__pycache__/irc.cpython-312.pyc     |    Bin [31m6046[m -> [32m0[m bytes
 .../formatters/__pycache__/latex.cpython-312.pyc   |    Bin [31m20116[m -> [32m0[m bytes
 .../formatters/__pycache__/other.cpython-312.pyc   |    Bin [31m6868[m -> [32m0[m bytes
 .../__pycache__/pangomarkup.cpython-312.pyc        |    Bin [31m2949[m -> [32m0[m bytes
 .../formatters/__pycache__/rtf.cpython-312.pyc     |    Bin [31m13764[m -> [32m0[m bytes
 .../formatters/__pycache__/svg.cpython-312.pyc     |    Bin [31m9130[m -> [32m0[m bytes
 .../__pycache__/terminal.cpython-312.pyc           |    Bin [31m5810[m -> [32m0[m bytes
 .../__pycache__/terminal256.cpython-312.pyc        |    Bin [31m15109[m -> [32m0[m bytes
 .../pip/_vendor/pygments/formatters/_mapping.py    |     23 [31m-[m
 .../pip/_vendor/pygments/formatters/bbcode.py      |    108 [31m-[m
 .../pip/_vendor/pygments/formatters/groff.py       |    170 [31m-[m
 .../pip/_vendor/pygments/formatters/html.py        |    987 [31m-[m
 .../pip/_vendor/pygments/formatters/img.py         |    685 [31m-[m
 .../pip/_vendor/pygments/formatters/irc.py         |    154 [31m-[m
 .../pip/_vendor/pygments/formatters/latex.py       |    518 [31m-[m
 .../pip/_vendor/pygments/formatters/other.py       |    160 [31m-[m
 .../pip/_vendor/pygments/formatters/pangomarkup.py |     83 [31m-[m
 .../pip/_vendor/pygments/formatters/rtf.py         |    349 [31m-[m
 .../pip/_vendor/pygments/formatters/svg.py         |    185 [31m-[m
 .../pip/_vendor/pygments/formatters/terminal.py    |    127 [31m-[m
 .../pip/_vendor/pygments/formatters/terminal256.py |    338 [31m-[m
 .../site-packages/pip/_vendor/pygments/lexer.py    |    963 [31m-[m
 .../pip/_vendor/pygments/lexers/__init__.py        |    362 [31m-[m
 .../lexers/__pycache__/__init__.cpython-312.pyc    |    Bin [31m14612[m -> [32m0[m bytes
 .../lexers/__pycache__/_mapping.cpython-312.pyc    |    Bin [31m68254[m -> [32m0[m bytes
 .../lexers/__pycache__/python.cpython-312.pyc      |    Bin [31m42958[m -> [32m0[m bytes
 .../pip/_vendor/pygments/lexers/_mapping.py        |    589 [31m-[m
 .../pip/_vendor/pygments/lexers/python.py          |   1198 [31m-[m
 .../site-packages/pip/_vendor/pygments/modeline.py |     43 [31m-[m
 .../site-packages/pip/_vendor/pygments/plugin.py   |     72 [31m-[m
 .../site-packages/pip/_vendor/pygments/regexopt.py |     91 [31m-[m
 .../site-packages/pip/_vendor/pygments/scanner.py  |    104 [31m-[m
 .../pip/_vendor/pygments/sphinxext.py              |    247 [31m-[m
 .../site-packages/pip/_vendor/pygments/style.py    |    203 [31m-[m
 .../pip/_vendor/pygments/styles/__init__.py        |     61 [31m-[m
 .../styles/__pycache__/__init__.cpython-312.pyc    |    Bin [31m2655[m -> [32m0[m bytes
 .../styles/__pycache__/_mapping.cpython-312.pyc    |    Bin [31m3639[m -> [32m0[m bytes
 .../pip/_vendor/pygments/styles/_mapping.py        |     54 [31m-[m
 .../site-packages/pip/_vendor/pygments/token.py    |    214 [31m-[m
 .../pip/_vendor/pygments/unistring.py              |    153 [31m-[m
 .../Lib/site-packages/pip/_vendor/pygments/util.py |    324 [31m-[m
 .../pip/_vendor/pyproject_hooks/__init__.py        |     31 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m738[m -> [32m0[m bytes
 .../__pycache__/_impl.cpython-312.pyc              |    Bin [31m18037[m -> [32m0[m bytes
 .../pip/_vendor/pyproject_hooks/_impl.py           |    410 [31m-[m
 .../pyproject_hooks/_in_process/__init__.py        |     21 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1067[m -> [32m0[m bytes
 .../__pycache__/_in_process.cpython-312.pyc        |    Bin [31m15305[m -> [32m0[m bytes
 .../pyproject_hooks/_in_process/_in_process.py     |    389 [31m-[m
 .../pip/_vendor/pyproject_hooks/py.typed           |      0
 .../site-packages/pip/_vendor/requests/__init__.py |    179 [31m-[m
 .../requests/__pycache__/__init__.cpython-312.pyc  |    Bin [31m5244[m -> [32m0[m bytes
 .../__pycache__/__version__.cpython-312.pyc        |    Bin [31m575[m -> [32m0[m bytes
 .../__pycache__/_internal_utils.cpython-312.pyc    |    Bin [31m2015[m -> [32m0[m bytes
 .../requests/__pycache__/adapters.cpython-312.pyc  |    Bin [31m28422[m -> [32m0[m bytes
 .../requests/__pycache__/api.cpython-312.pyc       |    Bin [31m7182[m -> [32m0[m bytes
 .../requests/__pycache__/auth.cpython-312.pyc      |    Bin [31m13912[m -> [32m0[m bytes
 .../requests/__pycache__/certs.cpython-312.pyc     |    Bin [31m669[m -> [32m0[m bytes
 .../requests/__pycache__/compat.cpython-312.pyc    |    Bin [31m1668[m -> [32m0[m bytes
 .../requests/__pycache__/cookies.cpython-312.pyc   |    Bin [31m25189[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m7589[m -> [32m0[m bytes
 .../requests/__pycache__/help.cpython-312.pyc      |    Bin [31m4219[m -> [32m0[m bytes
 .../requests/__pycache__/hooks.cpython-312.pyc     |    Bin [31m1042[m -> [32m0[m bytes
 .../requests/__pycache__/models.cpython-312.pyc    |    Bin [31m35419[m -> [32m0[m bytes
 .../requests/__pycache__/packages.cpython-312.pyc  |    Bin [31m1257[m -> [32m0[m bytes
 .../requests/__pycache__/sessions.cpython-312.pyc  |    Bin [31m27837[m -> [32m0[m bytes
 .../__pycache__/status_codes.cpython-312.pyc       |    Bin [31m6014[m -> [32m0[m bytes
 .../__pycache__/structures.cpython-312.pyc         |    Bin [31m5614[m -> [32m0[m bytes
 .../requests/__pycache__/utils.cpython-312.pyc     |    Bin [31m36357[m -> [32m0[m bytes
 .../pip/_vendor/requests/__version__.py            |     14 [31m-[m
 .../pip/_vendor/requests/_internal_utils.py        |     50 [31m-[m
 .../site-packages/pip/_vendor/requests/adapters.py |    719 [31m-[m
 .../Lib/site-packages/pip/_vendor/requests/api.py  |    157 [31m-[m
 .../Lib/site-packages/pip/_vendor/requests/auth.py |    314 [31m-[m
 .../site-packages/pip/_vendor/requests/certs.py    |     17 [31m-[m
 .../site-packages/pip/_vendor/requests/compat.py   |     78 [31m-[m
 .../site-packages/pip/_vendor/requests/cookies.py  |    561 [31m-[m
 .../pip/_vendor/requests/exceptions.py             |    151 [31m-[m
 .../Lib/site-packages/pip/_vendor/requests/help.py |    127 [31m-[m
 .../site-packages/pip/_vendor/requests/hooks.py    |     33 [31m-[m
 .../site-packages/pip/_vendor/requests/models.py   |   1037 [31m-[m
 .../site-packages/pip/_vendor/requests/packages.py |     25 [31m-[m
 .../site-packages/pip/_vendor/requests/sessions.py |    831 [31m-[m
 .../pip/_vendor/requests/status_codes.py           |    128 [31m-[m
 .../pip/_vendor/requests/structures.py             |     99 [31m-[m
 .../site-packages/pip/_vendor/requests/utils.py    |   1096 [31m-[m
 .../pip/_vendor/resolvelib/__init__.py             |     26 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m625[m -> [32m0[m bytes
 .../__pycache__/providers.cpython-312.pyc          |    Bin [31m6842[m -> [32m0[m bytes
 .../__pycache__/reporters.cpython-312.pyc          |    Bin [31m2645[m -> [32m0[m bytes
 .../__pycache__/resolvers.cpython-312.pyc          |    Bin [31m25871[m -> [32m0[m bytes
 .../resolvelib/__pycache__/structs.cpython-312.pyc |    Bin [31m10491[m -> [32m0[m bytes
 .../pip/_vendor/resolvelib/compat/__init__.py      |      0
 .../compat/__pycache__/__init__.cpython-312.pyc    |    Bin [31m191[m -> [32m0[m bytes
 .../__pycache__/collections_abc.cpython-312.pyc    |    Bin [31m411[m -> [32m0[m bytes
 .../_vendor/resolvelib/compat/collections_abc.py   |      6 [31m-[m
 .../pip/_vendor/resolvelib/providers.py            |    133 [31m-[m
 .../site-packages/pip/_vendor/resolvelib/py.typed  |      0
 .../pip/_vendor/resolvelib/reporters.py            |     43 [31m-[m
 .../pip/_vendor/resolvelib/resolvers.py            |    547 [31m-[m
 .../pip/_vendor/resolvelib/structs.py              |    170 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/__init__.py |    177 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/__main__.py |    273 [31m-[m
 .../rich/__pycache__/__init__.cpython-312.pyc      |    Bin [31m7006[m -> [32m0[m bytes
 .../rich/__pycache__/__main__.cpython-312.pyc      |    Bin [31m10283[m -> [32m0[m bytes
 .../rich/__pycache__/_cell_widths.cpython-312.pyc  |    Bin [31m7863[m -> [32m0[m bytes
 .../rich/__pycache__/_emoji_codes.cpython-312.pyc  |    Bin [31m205967[m -> [32m0[m bytes
 .../__pycache__/_emoji_replace.cpython-312.pyc     |    Bin [31m1720[m -> [32m0[m bytes
 .../__pycache__/_export_format.cpython-312.pyc     |    Bin [31m2340[m -> [32m0[m bytes
 .../rich/__pycache__/_extension.cpython-312.pyc    |    Bin [31m528[m -> [32m0[m bytes
 .../rich/__pycache__/_fileno.cpython-312.pyc       |    Bin [31m846[m -> [32m0[m bytes
 .../rich/__pycache__/_inspect.cpython-312.pyc      |    Bin [31m12013[m -> [32m0[m bytes
 .../rich/__pycache__/_log_render.cpython-312.pyc   |    Bin [31m4138[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/_loop.cpython-312.pyc |    Bin [31m1861[m -> [32m0[m bytes
 .../rich/__pycache__/_null_file.cpython-312.pyc    |    Bin [31m3620[m -> [32m0[m bytes
 .../rich/__pycache__/_palettes.cpython-312.pyc     |    Bin [31m5151[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/_pick.cpython-312.pyc |    Bin [31m712[m -> [32m0[m bytes
 .../rich/__pycache__/_ratio.cpython-312.pyc        |    Bin [31m6561[m -> [32m0[m bytes
 .../rich/__pycache__/_spinners.cpython-312.pyc     |    Bin [31m13170[m -> [32m0[m bytes
 .../rich/__pycache__/_stack.cpython-312.pyc        |    Bin [31m956[m -> [32m0[m bytes
 .../rich/__pycache__/_timer.cpython-312.pyc        |    Bin [31m856[m -> [32m0[m bytes
 .../__pycache__/_win32_console.cpython-312.pyc     |    Bin [31m28802[m -> [32m0[m bytes
 .../rich/__pycache__/_windows.cpython-312.pyc      |    Bin [31m2481[m -> [32m0[m bytes
 .../__pycache__/_windows_renderer.cpython-312.pyc  |    Bin [31m3554[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/_wrap.cpython-312.pyc |    Bin [31m3317[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/abc.cpython-312.pyc   |    Bin [31m1599[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/align.cpython-312.pyc |    Bin [31m12382[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/ansi.cpython-312.pyc  |    Bin [31m9072[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/bar.cpython-312.pyc   |    Bin [31m4263[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/box.cpython-312.pyc   |    Bin [31m11829[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/cells.cpython-312.pyc |    Bin [31m5551[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/color.cpython-312.pyc |    Bin [31m26543[m -> [32m0[m bytes
 .../rich/__pycache__/color_triplet.cpython-312.pyc |    Bin [31m1692[m -> [32m0[m bytes
 .../rich/__pycache__/columns.cpython-312.pyc       |    Bin [31m8575[m -> [32m0[m bytes
 .../rich/__pycache__/console.cpython-312.pyc       |    Bin [31m114536[m -> [32m0[m bytes
 .../rich/__pycache__/constrain.cpython-312.pyc     |    Bin [31m2249[m -> [32m0[m bytes
 .../rich/__pycache__/containers.cpython-312.pyc    |    Bin [31m9201[m -> [32m0[m bytes
 .../rich/__pycache__/control.cpython-312.pyc       |    Bin [31m10932[m -> [32m0[m bytes
 .../__pycache__/default_styles.cpython-312.pyc     |    Bin [31m10429[m -> [32m0[m bytes
 .../rich/__pycache__/diagnose.cpython-312.pyc      |    Bin [31m1479[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/emoji.cpython-312.pyc |    Bin [31m4203[m -> [32m0[m bytes
 .../rich/__pycache__/errors.cpython-312.pyc        |    Bin [31m1836[m -> [32m0[m bytes
 .../rich/__pycache__/file_proxy.cpython-312.pyc    |    Bin [31m3562[m -> [32m0[m bytes
 .../rich/__pycache__/filesize.cpython-312.pyc      |    Bin [31m3038[m -> [32m0[m bytes
 .../rich/__pycache__/highlighter.cpython-312.pyc   |    Bin [31m9879[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/json.cpython-312.pyc  |    Bin [31m6026[m -> [32m0[m bytes
 .../rich/__pycache__/jupyter.cpython-312.pyc       |    Bin [31m5199[m -> [32m0[m bytes
 .../rich/__pycache__/layout.cpython-312.pyc        |    Bin [31m20149[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/live.cpython-312.pyc  |    Bin [31m18999[m -> [32m0[m bytes
 .../rich/__pycache__/live_render.cpython-312.pyc   |    Bin [31m4880[m -> [32m0[m bytes
 .../rich/__pycache__/logging.cpython-312.pyc       |    Bin [31m14055[m -> [32m0[m bytes
 .../rich/__pycache__/markup.cpython-312.pyc        |    Bin [31m9558[m -> [32m0[m bytes
 .../rich/__pycache__/measure.cpython-312.pyc       |    Bin [31m6369[m -> [32m0[m bytes
 .../rich/__pycache__/padding.cpython-312.pyc       |    Bin [31m6924[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/pager.cpython-312.pyc |    Bin [31m1802[m -> [32m0[m bytes
 .../rich/__pycache__/palette.cpython-312.pyc       |    Bin [31m5288[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/panel.cpython-312.pyc |    Bin [31m12761[m -> [32m0[m bytes
 .../rich/__pycache__/pretty.cpython-312.pyc        |    Bin [31m40602[m -> [32m0[m bytes
 .../rich/__pycache__/progress.cpython-312.pyc      |    Bin [31m75725[m -> [32m0[m bytes
 .../rich/__pycache__/progress_bar.cpython-312.pyc  |    Bin [31m10368[m -> [32m0[m bytes
 .../rich/__pycache__/prompt.cpython-312.pyc        |    Bin [31m15996[m -> [32m0[m bytes
 .../rich/__pycache__/protocol.cpython-312.pyc      |    Bin [31m1783[m -> [32m0[m bytes
 .../rich/__pycache__/region.cpython-312.pyc        |    Bin [31m558[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/repr.cpython-312.pyc  |    Bin [31m6604[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/rule.cpython-312.pyc  |    Bin [31m6559[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/scope.cpython-312.pyc |    Bin [31m3816[m -> [32m0[m bytes
 .../rich/__pycache__/screen.cpython-312.pyc        |    Bin [31m2470[m -> [32m0[m bytes
 .../rich/__pycache__/segment.cpython-312.pyc       |    Bin [31m28528[m -> [32m0[m bytes
 .../rich/__pycache__/spinner.cpython-312.pyc       |    Bin [31m6081[m -> [32m0[m bytes
 .../rich/__pycache__/status.cpython-312.pyc        |    Bin [31m6052[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/style.cpython-312.pyc |    Bin [31m33467[m -> [32m0[m bytes
 .../rich/__pycache__/styled.cpython-312.pyc        |    Bin [31m2130[m -> [32m0[m bytes
 .../rich/__pycache__/syntax.cpython-312.pyc        |    Bin [31m40175[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/table.cpython-312.pyc |    Bin [31m43874[m -> [32m0[m bytes
 .../__pycache__/terminal_theme.cpython-312.pyc     |    Bin [31m3339[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/text.cpython-312.pyc  |    Bin [31m61201[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/theme.cpython-312.pyc |    Bin [31m6318[m -> [32m0[m bytes
 .../rich/__pycache__/themes.cpython-312.pyc        |    Bin [31m305[m -> [32m0[m bytes
 .../rich/__pycache__/traceback.cpython-312.pyc     |    Bin [31m32883[m -> [32m0[m bytes
 .../_vendor/rich/__pycache__/tree.cpython-312.pyc  |    Bin [31m11784[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/rich/_cell_widths.py |    454 [31m-[m
 .../site-packages/pip/_vendor/rich/_emoji_codes.py |   3610 [31m-[m
 .../pip/_vendor/rich/_emoji_replace.py             |     32 [31m-[m
 .../pip/_vendor/rich/_export_format.py             |     76 [31m-[m
 .../site-packages/pip/_vendor/rich/_extension.py   |     10 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_fileno.py  |     24 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_inspect.py |    268 [31m-[m
 .../site-packages/pip/_vendor/rich/_log_render.py  |     94 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_loop.py    |     43 [31m-[m
 .../site-packages/pip/_vendor/rich/_null_file.py   |     69 [31m-[m
 .../site-packages/pip/_vendor/rich/_palettes.py    |    309 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_pick.py    |     17 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_ratio.py   |    159 [31m-[m
 .../site-packages/pip/_vendor/rich/_spinners.py    |    482 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_stack.py   |     16 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_timer.py   |     19 [31m-[m
 .../pip/_vendor/rich/_win32_console.py             |    661 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_windows.py |     71 [31m-[m
 .../pip/_vendor/rich/_windows_renderer.py          |     56 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/_wrap.py    |     93 [31m-[m
 .../venv/Lib/site-packages/pip/_vendor/rich/abc.py |     33 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/align.py    |    312 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/ansi.py     |    241 [31m-[m
 .../venv/Lib/site-packages/pip/_vendor/rich/bar.py |     93 [31m-[m
 .../venv/Lib/site-packages/pip/_vendor/rich/box.py |    480 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/cells.py    |    174 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/color.py    |    621 [31m-[m
 .../pip/_vendor/rich/color_triplet.py              |     38 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/columns.py  |    187 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/console.py  |   2661 [31m-[m
 .../site-packages/pip/_vendor/rich/constrain.py    |     37 [31m-[m
 .../site-packages/pip/_vendor/rich/containers.py   |    167 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/control.py  |    225 [31m-[m
 .../pip/_vendor/rich/default_styles.py             |    191 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/diagnose.py |     37 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/emoji.py    |     96 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/errors.py   |     34 [31m-[m
 .../site-packages/pip/_vendor/rich/file_proxy.py   |     57 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/filesize.py |     88 [31m-[m
 .../site-packages/pip/_vendor/rich/highlighter.py  |    232 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/json.py     |    139 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/jupyter.py  |    101 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/layout.py   |    442 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/live.py     |    375 [31m-[m
 .../site-packages/pip/_vendor/rich/live_render.py  |    112 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/logging.py  |    297 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/markup.py   |    251 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/measure.py  |    151 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/padding.py  |    141 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/pager.py    |     34 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/palette.py  |    100 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/panel.py    |    318 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/pretty.py   |   1016 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/progress.py |   1715 [31m-[m
 .../site-packages/pip/_vendor/rich/progress_bar.py |    223 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/prompt.py   |    400 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/protocol.py |     42 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/py.typed    |      0
 .../Lib/site-packages/pip/_vendor/rich/region.py   |     10 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/repr.py     |    149 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/rule.py     |    130 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/scope.py    |     86 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/screen.py   |     54 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/segment.py  |    752 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/spinner.py  |    138 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/status.py   |    131 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/style.py    |    796 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/styled.py   |     42 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/syntax.py   |    966 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/table.py    |   1007 [31m-[m
 .../pip/_vendor/rich/terminal_theme.py             |    153 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/text.py     |   1361 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/theme.py    |    115 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/themes.py   |      5 [31m-[m
 .../site-packages/pip/_vendor/rich/traceback.py    |    797 [31m-[m
 .../Lib/site-packages/pip/_vendor/rich/tree.py     |    257 [31m-[m
 .../site-packages/pip/_vendor/tomli/__init__.py    |      8 [31m-[m
 .../tomli/__pycache__/__init__.cpython-312.pyc     |    Bin [31m329[m -> [32m0[m bytes
 .../tomli/__pycache__/_parser.cpython-312.pyc      |    Bin [31m29343[m -> [32m0[m bytes
 .../_vendor/tomli/__pycache__/_re.cpython-312.pyc  |    Bin [31m4030[m -> [32m0[m bytes
 .../tomli/__pycache__/_types.cpython-312.pyc       |    Bin [31m357[m -> [32m0[m bytes
 .../Lib/site-packages/pip/_vendor/tomli/_parser.py |    770 [31m-[m
 .../Lib/site-packages/pip/_vendor/tomli/_re.py     |    112 [31m-[m
 .../Lib/site-packages/pip/_vendor/tomli/_types.py  |     10 [31m-[m
 .../Lib/site-packages/pip/_vendor/tomli/py.typed   |      1 [31m-[m
 .../pip/_vendor/truststore/__init__.py             |     36 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1335[m -> [32m0[m bytes
 .../truststore/__pycache__/_api.cpython-312.pyc    |    Bin [31m16764[m -> [32m0[m bytes
 .../truststore/__pycache__/_macos.cpython-312.pyc  |    Bin [31m18978[m -> [32m0[m bytes
 .../__pycache__/_openssl.cpython-312.pyc           |    Bin [31m2196[m -> [32m0[m bytes
 .../__pycache__/_ssl_constants.cpython-312.pyc     |    Bin [31m1090[m -> [32m0[m bytes
 .../__pycache__/_windows.cpython-312.pyc           |    Bin [31m15756[m -> [32m0[m bytes
 .../site-packages/pip/_vendor/truststore/_api.py   |    316 [31m-[m
 .../site-packages/pip/_vendor/truststore/_macos.py |    571 [31m-[m
 .../pip/_vendor/truststore/_openssl.py             |     66 [31m-[m
 .../pip/_vendor/truststore/_ssl_constants.py       |     31 [31m-[m
 .../pip/_vendor/truststore/_windows.py             |    567 [31m-[m
 .../site-packages/pip/_vendor/truststore/py.typed  |      0
 .../site-packages/pip/_vendor/typing_extensions.py |   3641 [31m-[m
 .../site-packages/pip/_vendor/urllib3/__init__.py  |    102 [31m-[m
 .../urllib3/__pycache__/__init__.cpython-312.pyc   |    Bin [31m3396[m -> [32m0[m bytes
 .../__pycache__/_collections.cpython-312.pyc       |    Bin [31m16355[m -> [32m0[m bytes
 .../urllib3/__pycache__/_version.cpython-312.pyc   |    Bin [31m209[m -> [32m0[m bytes
 .../urllib3/__pycache__/connection.cpython-312.pyc |    Bin [31m20394[m -> [32m0[m bytes
 .../__pycache__/connectionpool.cpython-312.pyc     |    Bin [31m36529[m -> [32m0[m bytes
 .../urllib3/__pycache__/exceptions.cpython-312.pyc |    Bin [31m13484[m -> [32m0[m bytes
 .../urllib3/__pycache__/fields.cpython-312.pyc     |    Bin [31m10393[m -> [32m0[m bytes
 .../urllib3/__pycache__/filepost.cpython-312.pyc   |    Bin [31m4003[m -> [32m0[m bytes
 .../__pycache__/poolmanager.cpython-312.pyc        |    Bin [31m20420[m -> [32m0[m bytes
 .../urllib3/__pycache__/request.cpython-312.pyc    |    Bin [31m7285[m -> [32m0[m bytes
 .../urllib3/__pycache__/response.cpython-312.pyc   |    Bin [31m33934[m -> [32m0[m bytes
 .../pip/_vendor/urllib3/_collections.py            |    355 [31m-[m
 .../site-packages/pip/_vendor/urllib3/_version.py  |      2 [31m-[m
 .../pip/_vendor/urllib3/connection.py              |    572 [31m-[m
 .../pip/_vendor/urllib3/connectionpool.py          |   1140 [31m-[m
 .../pip/_vendor/urllib3/contrib/__init__.py        |      0
 .../contrib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m189[m -> [32m0[m bytes
 .../__pycache__/_appengine_environ.cpython-312.pyc |    Bin [31m1839[m -> [32m0[m bytes
 .../contrib/__pycache__/appengine.cpython-312.pyc  |    Bin [31m11555[m -> [32m0[m bytes
 .../contrib/__pycache__/ntlmpool.cpython-312.pyc   |    Bin [31m5705[m -> [32m0[m bytes
 .../contrib/__pycache__/pyopenssl.cpython-312.pyc  |    Bin [31m24439[m -> [32m0[m bytes
 .../__pycache__/securetransport.cpython-312.pyc    |    Bin [31m35492[m -> [32m0[m bytes
 .../contrib/__pycache__/socks.cpython-312.pyc      |    Bin [31m7502[m -> [32m0[m bytes
 .../_vendor/urllib3/contrib/_appengine_environ.py  |     36 [31m-[m
 .../urllib3/contrib/_securetransport/__init__.py   |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m206[m -> [32m0[m bytes
 .../__pycache__/bindings.cpython-312.pyc           |    Bin [31m17418[m -> [32m0[m bytes
 .../__pycache__/low_level.cpython-312.pyc          |    Bin [31m14754[m -> [32m0[m bytes
 .../urllib3/contrib/_securetransport/bindings.py   |    519 [31m-[m
 .../urllib3/contrib/_securetransport/low_level.py  |    397 [31m-[m
 .../pip/_vendor/urllib3/contrib/appengine.py       |    314 [31m-[m
 .../pip/_vendor/urllib3/contrib/ntlmpool.py        |    130 [31m-[m
 .../pip/_vendor/urllib3/contrib/pyopenssl.py       |    518 [31m-[m
 .../pip/_vendor/urllib3/contrib/securetransport.py |    920 [31m-[m
 .../pip/_vendor/urllib3/contrib/socks.py           |    216 [31m-[m
 .../pip/_vendor/urllib3/exceptions.py              |    323 [31m-[m
 .../site-packages/pip/_vendor/urllib3/fields.py    |    274 [31m-[m
 .../site-packages/pip/_vendor/urllib3/filepost.py  |     98 [31m-[m
 .../pip/_vendor/urllib3/packages/__init__.py       |      0
 .../packages/__pycache__/__init__.cpython-312.pyc  |    Bin [31m190[m -> [32m0[m bytes
 .../packages/__pycache__/six.cpython-312.pyc       |    Bin [31m41246[m -> [32m0[m bytes
 .../_vendor/urllib3/packages/backports/__init__.py |      0
 .../backports/__pycache__/__init__.cpython-312.pyc |    Bin [31m200[m -> [32m0[m bytes
 .../backports/__pycache__/makefile.cpython-312.pyc |    Bin [31m1816[m -> [32m0[m bytes
 .../__pycache__/weakref_finalize.cpython-312.pyc   |    Bin [31m7327[m -> [32m0[m bytes
 .../_vendor/urllib3/packages/backports/makefile.py |     51 [31m-[m
 .../urllib3/packages/backports/weakref_finalize.py |    155 [31m-[m
 .../pip/_vendor/urllib3/packages/six.py            |   1076 [31m-[m
 .../pip/_vendor/urllib3/poolmanager.py             |    540 [31m-[m
 .../site-packages/pip/_vendor/urllib3/request.py   |    191 [31m-[m
 .../site-packages/pip/_vendor/urllib3/response.py  |    879 [31m-[m
 .../pip/_vendor/urllib3/util/__init__.py           |     49 [31m-[m
 .../util/__pycache__/__init__.cpython-312.pyc      |    Bin [31m1137[m -> [32m0[m bytes
 .../util/__pycache__/connection.cpython-312.pyc    |    Bin [31m4738[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/proxy.cpython-312.pyc |    Bin [31m1543[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/queue.cpython-312.pyc |    Bin [31m1343[m -> [32m0[m bytes
 .../util/__pycache__/request.cpython-312.pyc       |    Bin [31m4174[m -> [32m0[m bytes
 .../util/__pycache__/response.cpython-312.pyc      |    Bin [31m2983[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/retry.cpython-312.pyc |    Bin [31m21713[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/ssl_.cpython-312.pyc  |    Bin [31m15355[m -> [32m0[m bytes
 .../__pycache__/ssl_match_hostname.cpython-312.pyc |    Bin [31m5042[m -> [32m0[m bytes
 .../util/__pycache__/ssltransport.cpython-312.pyc  |    Bin [31m10744[m -> [32m0[m bytes
 .../util/__pycache__/timeout.cpython-312.pyc       |    Bin [31m11130[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/url.cpython-312.pyc   |    Bin [31m15776[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/wait.cpython-312.pyc  |    Bin [31m4394[m -> [32m0[m bytes
 .../pip/_vendor/urllib3/util/connection.py         |    149 [31m-[m
 .../pip/_vendor/urllib3/util/proxy.py              |     57 [31m-[m
 .../pip/_vendor/urllib3/util/queue.py              |     22 [31m-[m
 .../pip/_vendor/urllib3/util/request.py            |    137 [31m-[m
 .../pip/_vendor/urllib3/util/response.py           |    107 [31m-[m
 .../pip/_vendor/urllib3/util/retry.py              |    622 [31m-[m
 .../site-packages/pip/_vendor/urllib3/util/ssl_.py |    504 [31m-[m
 .../pip/_vendor/urllib3/util/ssl_match_hostname.py |    159 [31m-[m
 .../pip/_vendor/urllib3/util/ssltransport.py       |    221 [31m-[m
 .../pip/_vendor/urllib3/util/timeout.py            |    271 [31m-[m
 .../site-packages/pip/_vendor/urllib3/util/url.py  |    435 [31m-[m
 .../site-packages/pip/_vendor/urllib3/util/wait.py |    152 [31m-[m
 .../venv/Lib/site-packages/pip/_vendor/vendor.txt  |     18 [31m-[m
 backend/venv/Lib/site-packages/pip/py.typed        |      4 [31m-[m
 .../site-packages/pluggy-1.6.0.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/pluggy-1.6.0.dist-info/METADATA  |    152 [31m-[m
 .../site-packages/pluggy-1.6.0.dist-info/RECORD    |     23 [31m-[m
 .../Lib/site-packages/pluggy-1.6.0.dist-info/WHEEL |      5 [31m-[m
 .../pluggy-1.6.0.dist-info/licenses/LICENSE        |     21 [31m-[m
 .../pluggy-1.6.0.dist-info/top_level.txt           |      1 [31m-[m
 backend/venv/Lib/site-packages/pluggy/__init__.py  |     30 [31m-[m
 .../pluggy/__pycache__/__init__.cpython-312.pyc    |    Bin [31m844[m -> [32m0[m bytes
 .../pluggy/__pycache__/_callers.cpython-312.pyc    |    Bin [31m6999[m -> [32m0[m bytes
 .../pluggy/__pycache__/_hooks.cpython-312.pyc      |    Bin [31m27401[m -> [32m0[m bytes
 .../pluggy/__pycache__/_manager.cpython-312.pyc    |    Bin [31m25563[m -> [32m0[m bytes
 .../pluggy/__pycache__/_result.cpython-312.pyc     |    Bin [31m4131[m -> [32m0[m bytes
 .../pluggy/__pycache__/_tracing.cpython-312.pyc    |    Bin [31m4003[m -> [32m0[m bytes
 .../pluggy/__pycache__/_version.cpython-312.pyc    |    Bin [31m629[m -> [32m0[m bytes
 .../pluggy/__pycache__/_warnings.cpython-312.pyc   |    Bin [31m1282[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pluggy/_callers.py  |    169 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_hooks.py    |    714 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_manager.py  |    523 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_result.py   |    107 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_tracing.py  |     72 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_version.py  |     21 [31m-[m
 backend/venv/Lib/site-packages/pluggy/_warnings.py |     27 [31m-[m
 backend/venv/Lib/site-packages/pluggy/py.typed     |      0
 .../propcache-0.4.1.dist-info/INSTALLER            |      1 [31m-[m
 .../propcache-0.4.1.dist-info/METADATA             |    443 [31m-[m
 .../site-packages/propcache-0.4.1.dist-info/RECORD |     18 [31m-[m
 .../site-packages/propcache-0.4.1.dist-info/WHEEL  |      5 [31m-[m
 .../propcache-0.4.1.dist-info/licenses/LICENSE     |    202 [31m-[m
 .../propcache-0.4.1.dist-info/licenses/NOTICE      |     13 [31m-[m
 .../propcache-0.4.1.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/propcache/__init__.py   |     32 [31m-[m
 .../propcache/__pycache__/__init__.cpython-312.pyc |    Bin [31m1269[m -> [32m0[m bytes
 .../propcache/__pycache__/_helpers.cpython-312.pyc |    Bin [31m1012[m -> [32m0[m bytes
 .../__pycache__/_helpers_py.cpython-312.pyc        |    Bin [31m3190[m -> [32m0[m bytes
 .../propcache/__pycache__/api.cpython-312.pyc      |    Bin [31m330[m -> [32m0[m bytes
 .../venv/Lib/site-packages/propcache/_helpers.py   |     39 [31m-[m
 .../propcache/_helpers_c.cp312-win_amd64.pyd       |    Bin [31m65024[m -> [32m0[m bytes
 .../Lib/site-packages/propcache/_helpers_c.pyx     |    103 [31m-[m
 .../Lib/site-packages/propcache/_helpers_py.py     |     62 [31m-[m
 backend/venv/Lib/site-packages/propcache/api.py    |      8 [31m-[m
 backend/venv/Lib/site-packages/propcache/py.typed  |      1 [31m-[m
 backend/venv/Lib/site-packages/proto/__init__.py   |     72 [31m-[m
 .../proto/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1402[m -> [32m0[m bytes
 .../proto/__pycache__/_file_info.cpython-312.pyc   |    Bin [31m8211[m -> [32m0[m bytes
 .../__pycache__/_package_info.cpython-312.pyc      |    Bin [31m1318[m -> [32m0[m bytes
 .../__pycache__/datetime_helpers.cpython-312.pyc   |    Bin [31m8642[m -> [32m0[m bytes
 .../proto/__pycache__/enums.cpython-312.pyc        |    Bin [31m6406[m -> [32m0[m bytes
 .../proto/__pycache__/fields.cpython-312.pyc       |    Bin [31m5381[m -> [32m0[m bytes
 .../proto/__pycache__/message.cpython-312.pyc      |    Bin [31m36685[m -> [32m0[m bytes
 .../proto/__pycache__/modules.cpython-312.pyc      |    Bin [31m1287[m -> [32m0[m bytes
 .../proto/__pycache__/primitives.cpython-312.pyc   |    Bin [31m834[m -> [32m0[m bytes
 .../proto/__pycache__/utils.cpython-312.pyc        |    Bin [31m1496[m -> [32m0[m bytes
 .../proto/__pycache__/version.cpython-312.pyc      |    Bin [31m195[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/proto/_file_info.py |    196 [31m-[m
 .../venv/Lib/site-packages/proto/_package_info.py  |     50 [31m-[m
 .../Lib/site-packages/proto/datetime_helpers.py    |    225 [31m-[m
 backend/venv/Lib/site-packages/proto/enums.py      |    165 [31m-[m
 backend/venv/Lib/site-packages/proto/fields.py     |    165 [31m-[m
 .../Lib/site-packages/proto/marshal/__init__.py    |     18 [31m-[m
 .../marshal/__pycache__/__init__.cpython-312.pyc   |    Bin [31m239[m -> [32m0[m bytes
 .../marshal/__pycache__/compat.cpython-312.pyc     |    Bin [31m1226[m -> [32m0[m bytes
 .../marshal/__pycache__/marshal.cpython-312.pyc    |    Bin [31m12972[m -> [32m0[m bytes
 .../proto/marshal/collections/__init__.py          |     24 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m353[m -> [32m0[m bytes
 .../collections/__pycache__/maps.cpython-312.pyc   |    Bin [31m3378[m -> [32m0[m bytes
 .../__pycache__/repeated.cpython-312.pyc           |    Bin [31m8093[m -> [32m0[m bytes
 .../proto/marshal/collections/maps.py              |     82 [31m-[m
 .../proto/marshal/collections/repeated.py          |    189 [31m-[m
 .../venv/Lib/site-packages/proto/marshal/compat.py |     64 [31m-[m
 .../Lib/site-packages/proto/marshal/marshal.py     |    297 [31m-[m
 .../site-packages/proto/marshal/rules/__init__.py  |     13 [31m-[m
 .../rules/__pycache__/__init__.cpython-312.pyc     |    Bin [31m181[m -> [32m0[m bytes
 .../rules/__pycache__/bytes.cpython-312.pyc        |    Bin [31m1651[m -> [32m0[m bytes
 .../rules/__pycache__/dates.cpython-312.pyc        |    Bin [31m3805[m -> [32m0[m bytes
 .../rules/__pycache__/enums.cpython-312.pyc        |    Bin [31m1785[m -> [32m0[m bytes
 .../rules/__pycache__/field_mask.cpython-312.pyc   |    Bin [31m1206[m -> [32m0[m bytes
 .../rules/__pycache__/message.cpython-312.pyc      |    Bin [31m2159[m -> [32m0[m bytes
 .../__pycache__/stringy_numbers.cpython-312.pyc    |    Bin [31m2367[m -> [32m0[m bytes
 .../rules/__pycache__/struct.cpython-312.pyc       |    Bin [31m6828[m -> [32m0[m bytes
 .../rules/__pycache__/wrappers.cpython-312.pyc     |    Bin [31m3427[m -> [32m0[m bytes
 .../Lib/site-packages/proto/marshal/rules/bytes.py |     44 [31m-[m
 .../Lib/site-packages/proto/marshal/rules/dates.py |     85 [31m-[m
 .../Lib/site-packages/proto/marshal/rules/enums.py |     59 [31m-[m
 .../proto/marshal/rules/field_mask.py              |     36 [31m-[m
 .../site-packages/proto/marshal/rules/message.py   |     53 [31m-[m
 .../proto/marshal/rules/stringy_numbers.py         |     71 [31m-[m
 .../site-packages/proto/marshal/rules/struct.py    |    143 [31m-[m
 .../site-packages/proto/marshal/rules/wrappers.py  |     84 [31m-[m
 backend/venv/Lib/site-packages/proto/message.py    |    969 [31m-[m
 backend/venv/Lib/site-packages/proto/modules.py    |     50 [31m-[m
 backend/venv/Lib/site-packages/proto/primitives.py |     38 [31m-[m
 backend/venv/Lib/site-packages/proto/utils.py      |     58 [31m-[m
 backend/venv/Lib/site-packages/proto/version.py    |     15 [31m-[m
 .../proto_plus-1.27.0.dist-info/INSTALLER          |      1 [31m-[m
 .../proto_plus-1.27.0.dist-info/METADATA           |     58 [31m-[m
 .../proto_plus-1.27.0.dist-info/RECORD             |     58 [31m-[m
 .../proto_plus-1.27.0.dist-info/WHEEL              |      5 [31m-[m
 .../proto_plus-1.27.0.dist-info/licenses/LICENSE   |    202 [31m-[m
 .../proto_plus-1.27.0.dist-info/top_level.txt      |      1 [31m-[m
 .../protobuf-5.29.5.dist-info/INSTALLER            |      1 [31m-[m
 .../protobuf-5.29.5.dist-info/LICENSE              |     32 [31m-[m
 .../protobuf-5.29.5.dist-info/METADATA             |     17 [31m-[m
 .../site-packages/protobuf-5.29.5.dist-info/RECORD |    116 [31m-[m
 .../site-packages/protobuf-5.29.5.dist-info/WHEEL  |      4 [31m-[m
 backend/venv/Lib/site-packages/py.py               |     15 [31m-[m
 .../site-packages/pyasn1-0.6.1.dist-info/INSTALLER |      1 [31m-[m
 .../pyasn1-0.6.1.dist-info/LICENSE.rst             |     24 [31m-[m
 .../site-packages/pyasn1-0.6.1.dist-info/METADATA  |    228 [31m-[m
 .../site-packages/pyasn1-0.6.1.dist-info/RECORD    |     71 [31m-[m
 .../Lib/site-packages/pyasn1-0.6.1.dist-info/WHEEL |      5 [31m-[m
 .../pyasn1-0.6.1.dist-info/top_level.txt           |      1 [31m-[m
 .../site-packages/pyasn1-0.6.1.dist-info/zip-safe  |      1 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/__init__.py  |      2 [31m-[m
 .../pyasn1/__pycache__/__init__.cpython-312.pyc    |    Bin [31m194[m -> [32m0[m bytes
 .../pyasn1/__pycache__/debug.cpython-312.pyc       |    Bin [31m6053[m -> [32m0[m bytes
 .../pyasn1/__pycache__/error.cpython-312.pyc       |    Bin [31m4619[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/codec/__init__.py     |      1 [31m-[m
 .../codec/__pycache__/__init__.cpython-312.pyc     |    Bin [31m174[m -> [32m0[m bytes
 .../codec/__pycache__/streaming.cpython-312.pyc    |    Bin [31m8420[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/codec/ber/__init__.py |      1 [31m-[m
 .../codec/ber/__pycache__/__init__.cpython-312.pyc |    Bin [31m178[m -> [32m0[m bytes
 .../codec/ber/__pycache__/decoder.cpython-312.pyc  |    Bin [31m74033[m -> [32m0[m bytes
 .../codec/ber/__pycache__/encoder.cpython-312.pyc  |    Bin [31m31931[m -> [32m0[m bytes
 .../codec/ber/__pycache__/eoo.cpython-312.pyc      |    Bin [31m1102[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/codec/ber/decoder.py  |   2189 [31m-[m
 .../Lib/site-packages/pyasn1/codec/ber/encoder.py  |    954 [31m-[m
 .../venv/Lib/site-packages/pyasn1/codec/ber/eoo.py |     28 [31m-[m
 .../Lib/site-packages/pyasn1/codec/cer/__init__.py |      1 [31m-[m
 .../codec/cer/__pycache__/__init__.cpython-312.pyc |    Bin [31m178[m -> [32m0[m bytes
 .../codec/cer/__pycache__/decoder.cpython-312.pyc  |    Bin [31m4100[m -> [32m0[m bytes
 .../codec/cer/__pycache__/encoder.cpython-312.pyc  |    Bin [31m11578[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/codec/cer/decoder.py  |    149 [31m-[m
 .../Lib/site-packages/pyasn1/codec/cer/encoder.py  |    331 [31m-[m
 .../Lib/site-packages/pyasn1/codec/der/__init__.py |      1 [31m-[m
 .../codec/der/__pycache__/__init__.cpython-312.pyc |    Bin [31m178[m -> [32m0[m bytes
 .../codec/der/__pycache__/decoder.cpython-312.pyc  |    Bin [31m3041[m -> [32m0[m bytes
 .../codec/der/__pycache__/encoder.cpython-312.pyc  |    Bin [31m3245[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/codec/der/decoder.py  |    120 [31m-[m
 .../Lib/site-packages/pyasn1/codec/der/encoder.py  |    126 [31m-[m
 .../site-packages/pyasn1/codec/native/__init__.py  |      1 [31m-[m
 .../native/__pycache__/__init__.cpython-312.pyc    |    Bin [31m181[m -> [32m0[m bytes
 .../native/__pycache__/decoder.cpython-312.pyc     |    Bin [31m11776[m -> [32m0[m bytes
 .../native/__pycache__/encoder.cpython-312.pyc     |    Bin [31m14282[m -> [32m0[m bytes
 .../site-packages/pyasn1/codec/native/decoder.py   |    244 [31m-[m
 .../site-packages/pyasn1/codec/native/encoder.py   |    285 [31m-[m
 .../Lib/site-packages/pyasn1/codec/streaming.py    |    234 [31m-[m
 .../Lib/site-packages/pyasn1/compat/__init__.py    |      4 [31m-[m
 .../compat/__pycache__/__init__.cpython-312.pyc    |    Bin [31m213[m -> [32m0[m bytes
 .../compat/__pycache__/integer.cpython-312.pyc     |    Bin [31m593[m -> [32m0[m bytes
 .../Lib/site-packages/pyasn1/compat/integer.py     |     13 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/debug.py     |    146 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/error.py     |    116 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/__init__.py |      1 [31m-[m
 .../type/__pycache__/__init__.cpython-312.pyc      |    Bin [31m173[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/base.cpython-312.pyc   |    Bin [31m27823[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/char.cpython-312.pyc   |    Bin [31m9662[m -> [32m0[m bytes
 .../type/__pycache__/constraint.cpython-312.pyc    |    Bin [31m28505[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/error.cpython-312.pyc  |    Bin [31m412[m -> [32m0[m bytes
 .../type/__pycache__/namedtype.cpython-312.pyc     |    Bin [31m23956[m -> [32m0[m bytes
 .../type/__pycache__/namedval.cpython-312.pyc      |    Bin [31m7735[m -> [32m0[m bytes
 .../type/__pycache__/opentype.cpython-312.pyc      |    Bin [31m3892[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/tag.cpython-312.pyc    |    Bin [31m13161[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/tagmap.cpython-312.pyc |    Bin [31m4373[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/univ.cpython-312.pyc   |    Bin [31m132571[m -> [32m0[m bytes
 .../pyasn1/type/__pycache__/useful.cpython-312.pyc |    Bin [31m7437[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pyasn1/type/base.py |    699 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/type/char.py |    288 [31m-[m
 .../Lib/site-packages/pyasn1/type/constraint.py    |    751 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/error.py    |     11 [31m-[m
 .../Lib/site-packages/pyasn1/type/namedtype.py     |    550 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/namedval.py |    192 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/opentype.py |    104 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/type/tag.py  |    335 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/tagmap.py   |     96 [31m-[m
 backend/venv/Lib/site-packages/pyasn1/type/univ.py |   3327 [31m-[m
 .../venv/Lib/site-packages/pyasn1/type/useful.py   |    189 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/INSTALLER       |      1 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/METADATA        |     73 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/RECORD          |    271 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/WHEEL           |      5 [31m-[m
 .../licenses/LICENSE.txt                           |     24 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/top_level.txt   |      1 [31m-[m
 .../pyasn1_modules-0.4.2.dist-info/zip-safe        |      1 [31m-[m
 .../Lib/site-packages/pyasn1_modules/__init__.py   |      2 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m202[m -> [32m0[m bytes
 .../pyasn1_modules/__pycache__/pem.cpython-312.pyc |    Bin [31m2777[m -> [32m0[m bytes
 .../__pycache__/rfc1155.cpython-312.pyc            |    Bin [31m5197[m -> [32m0[m bytes
 .../__pycache__/rfc1157.cpython-312.pyc            |    Bin [31m6597[m -> [32m0[m bytes
 .../__pycache__/rfc1901.cpython-312.pyc            |    Bin [31m1031[m -> [32m0[m bytes
 .../__pycache__/rfc1902.cpython-312.pyc            |    Bin [31m6870[m -> [32m0[m bytes
 .../__pycache__/rfc1905.cpython-312.pyc            |    Bin [31m8334[m -> [32m0[m bytes
 .../__pycache__/rfc2251.cpython-312.pyc            |    Bin [31m36390[m -> [32m0[m bytes
 .../__pycache__/rfc2314.cpython-312.pyc            |    Bin [31m2406[m -> [32m0[m bytes
 .../__pycache__/rfc2315.cpython-312.pyc            |    Bin [31m17139[m -> [32m0[m bytes
 .../__pycache__/rfc2437.cpython-312.pyc            |    Bin [31m4374[m -> [32m0[m bytes
 .../__pycache__/rfc2459.cpython-312.pyc            |    Bin [31m87619[m -> [32m0[m bytes
 .../__pycache__/rfc2511.cpython-312.pyc            |    Bin [31m18635[m -> [32m0[m bytes
 .../__pycache__/rfc2560.cpython-312.pyc            |    Bin [31m14869[m -> [32m0[m bytes
 .../__pycache__/rfc2631.cpython-312.pyc            |    Bin [31m1999[m -> [32m0[m bytes
 .../__pycache__/rfc2634.cpython-312.pyc            |    Bin [31m14172[m -> [32m0[m bytes
 .../__pycache__/rfc2876.cpython-312.pyc            |    Bin [31m1673[m -> [32m0[m bytes
 .../__pycache__/rfc2985.cpython-312.pyc            |    Bin [31m15107[m -> [32m0[m bytes
 .../__pycache__/rfc2986.cpython-312.pyc            |    Bin [31m2493[m -> [32m0[m bytes
 .../__pycache__/rfc3058.cpython-312.pyc            |    Bin [31m1182[m -> [32m0[m bytes
 .../__pycache__/rfc3114.cpython-312.pyc            |    Bin [31m2267[m -> [32m0[m bytes
 .../__pycache__/rfc3125.cpython-312.pyc            |    Bin [31m28751[m -> [32m0[m bytes
 .../__pycache__/rfc3161.cpython-312.pyc            |    Bin [31m7331[m -> [32m0[m bytes
 .../__pycache__/rfc3274.cpython-312.pyc            |    Bin [31m1709[m -> [32m0[m bytes
 .../__pycache__/rfc3279.cpython-312.pyc            |    Bin [31m12039[m -> [32m0[m bytes
 .../__pycache__/rfc3280.cpython-312.pyc            |    Bin [31m77182[m -> [32m0[m bytes
 .../__pycache__/rfc3281.cpython-312.pyc            |    Bin [31m16944[m -> [32m0[m bytes
 .../__pycache__/rfc3370.cpython-312.pyc            |    Bin [31m3187[m -> [32m0[m bytes
 .../__pycache__/rfc3412.cpython-312.pyc            |    Bin [31m3429[m -> [32m0[m bytes
 .../__pycache__/rfc3414.cpython-312.pyc            |    Bin [31m1742[m -> [32m0[m bytes
 .../__pycache__/rfc3447.cpython-312.pyc            |    Bin [31m2662[m -> [32m0[m bytes
 .../__pycache__/rfc3537.cpython-312.pyc            |    Bin [31m804[m -> [32m0[m bytes
 .../__pycache__/rfc3560.cpython-312.pyc            |    Bin [31m1819[m -> [32m0[m bytes
 .../__pycache__/rfc3565.cpython-312.pyc            |    Bin [31m1760[m -> [32m0[m bytes
 .../__pycache__/rfc3657.cpython-312.pyc            |    Bin [31m1985[m -> [32m0[m bytes
 .../__pycache__/rfc3709.cpython-312.pyc            |    Bin [31m10529[m -> [32m0[m bytes
 .../__pycache__/rfc3739.cpython-312.pyc            |    Bin [31m6965[m -> [32m0[m bytes
 .../__pycache__/rfc3770.cpython-312.pyc            |    Bin [31m1710[m -> [32m0[m bytes
 .../__pycache__/rfc3779.cpython-312.pyc            |    Bin [31m5290[m -> [32m0[m bytes
 .../__pycache__/rfc3820.cpython-312.pyc            |    Bin [31m2079[m -> [32m0[m bytes
 .../__pycache__/rfc3852.cpython-312.pyc            |    Bin [31m34683[m -> [32m0[m bytes
 .../__pycache__/rfc4010.cpython-312.pyc            |    Bin [31m1618[m -> [32m0[m bytes
 .../__pycache__/rfc4043.cpython-312.pyc            |    Bin [31m1263[m -> [32m0[m bytes
 .../__pycache__/rfc4055.cpython-312.pyc            |    Bin [31m12047[m -> [32m0[m bytes
 .../__pycache__/rfc4073.cpython-312.pyc            |    Bin [31m1898[m -> [32m0[m bytes
 .../__pycache__/rfc4108.cpython-312.pyc            |    Bin [31m14109[m -> [32m0[m bytes
 .../__pycache__/rfc4210.cpython-312.pyc            |    Bin [31m41103[m -> [32m0[m bytes
 .../__pycache__/rfc4211.cpython-312.pyc            |    Bin [31m21158[m -> [32m0[m bytes
 .../__pycache__/rfc4334.cpython-312.pyc            |    Bin [31m1742[m -> [32m0[m bytes
 .../__pycache__/rfc4357.cpython-312.pyc            |    Bin [31m16840[m -> [32m0[m bytes
 .../__pycache__/rfc4387.cpython-312.pyc            |    Bin [31m432[m -> [32m0[m bytes
 .../__pycache__/rfc4476.cpython-312.pyc            |    Bin [31m2741[m -> [32m0[m bytes
 .../__pycache__/rfc4490.cpython-312.pyc            |    Bin [31m4276[m -> [32m0[m bytes
 .../__pycache__/rfc4491.cpython-312.pyc            |    Bin [31m749[m -> [32m0[m bytes
 .../__pycache__/rfc4683.cpython-312.pyc            |    Bin [31m2617[m -> [32m0[m bytes
 .../__pycache__/rfc4985.cpython-312.pyc            |    Bin [31m1104[m -> [32m0[m bytes
 .../__pycache__/rfc5035.cpython-312.pyc            |    Bin [31m4798[m -> [32m0[m bytes
 .../__pycache__/rfc5083.cpython-312.pyc            |    Bin [31m2482[m -> [32m0[m bytes
 .../__pycache__/rfc5084.cpython-312.pyc            |    Bin [31m3283[m -> [32m0[m bytes
 .../__pycache__/rfc5126.cpython-312.pyc            |    Bin [31m24988[m -> [32m0[m bytes
 .../__pycache__/rfc5208.cpython-312.pyc            |    Bin [31m2844[m -> [32m0[m bytes
 .../__pycache__/rfc5275.cpython-312.pyc            |    Bin [31m16419[m -> [32m0[m bytes
 .../__pycache__/rfc5280.cpython-312.pyc            |    Bin [31m80537[m -> [32m0[m bytes
 .../__pycache__/rfc5480.cpython-312.pyc            |    Bin [31m5280[m -> [32m0[m bytes
 .../__pycache__/rfc5636.cpython-312.pyc            |    Bin [31m3599[m -> [32m0[m bytes
 .../__pycache__/rfc5639.cpython-312.pyc            |    Bin [31m1042[m -> [32m0[m bytes
 .../__pycache__/rfc5649.cpython-312.pyc            |    Bin [31m1092[m -> [32m0[m bytes
 .../__pycache__/rfc5652.cpython-312.pyc            |    Bin [31m35743[m -> [32m0[m bytes
 .../__pycache__/rfc5697.cpython-312.pyc            |    Bin [31m2196[m -> [32m0[m bytes
 .../__pycache__/rfc5751.cpython-312.pyc            |    Bin [31m3984[m -> [32m0[m bytes
 .../__pycache__/rfc5752.cpython-312.pyc            |    Bin [31m1927[m -> [32m0[m bytes
 .../__pycache__/rfc5753.cpython-312.pyc            |    Bin [31m5063[m -> [32m0[m bytes
 .../__pycache__/rfc5755.cpython-312.pyc            |    Bin [31m19064[m -> [32m0[m bytes
 .../__pycache__/rfc5913.cpython-312.pyc            |    Bin [31m1145[m -> [32m0[m bytes
 .../__pycache__/rfc5914.cpython-312.pyc            |    Bin [31m6092[m -> [32m0[m bytes
 .../__pycache__/rfc5915.cpython-312.pyc            |    Bin [31m1662[m -> [32m0[m bytes
 .../__pycache__/rfc5916.cpython-312.pyc            |    Bin [31m797[m -> [32m0[m bytes
 .../__pycache__/rfc5917.cpython-312.pyc            |    Bin [31m1534[m -> [32m0[m bytes
 .../__pycache__/rfc5924.cpython-312.pyc            |    Bin [31m360[m -> [32m0[m bytes
 .../__pycache__/rfc5934.cpython-312.pyc            |    Bin [31m34529[m -> [32m0[m bytes
 .../__pycache__/rfc5940.cpython-312.pyc            |    Bin [31m1560[m -> [32m0[m bytes
 .../__pycache__/rfc5958.cpython-312.pyc            |    Bin [31m4293[m -> [32m0[m bytes
 .../__pycache__/rfc5990.cpython-312.pyc            |    Bin [31m6684[m -> [32m0[m bytes
 .../__pycache__/rfc6010.cpython-312.pyc            |    Bin [31m3130[m -> [32m0[m bytes
 .../__pycache__/rfc6019.cpython-312.pyc            |    Bin [31m1105[m -> [32m0[m bytes
 .../__pycache__/rfc6031.cpython-312.pyc            |    Bin [31m19592[m -> [32m0[m bytes
 .../__pycache__/rfc6032.cpython-312.pyc            |    Bin [31m2388[m -> [32m0[m bytes
 .../__pycache__/rfc6120.cpython-312.pyc            |    Bin [31m828[m -> [32m0[m bytes
 .../__pycache__/rfc6170.cpython-312.pyc            |    Bin [31m333[m -> [32m0[m bytes
 .../__pycache__/rfc6187.cpython-312.pyc            |    Bin [31m453[m -> [32m0[m bytes
 .../__pycache__/rfc6210.cpython-312.pyc            |    Bin [31m1125[m -> [32m0[m bytes
 .../__pycache__/rfc6211.cpython-312.pyc            |    Bin [31m2537[m -> [32m0[m bytes
 .../__pycache__/rfc6402.cpython-312.pyc            |    Bin [31m26260[m -> [32m0[m bytes
 .../__pycache__/rfc6482.cpython-312.pyc            |    Bin [31m3421[m -> [32m0[m bytes
 .../__pycache__/rfc6486.cpython-312.pyc            |    Bin [31m2916[m -> [32m0[m bytes
 .../__pycache__/rfc6487.cpython-312.pyc            |    Bin [31m444[m -> [32m0[m bytes
 .../__pycache__/rfc6664.cpython-312.pyc            |    Bin [31m5308[m -> [32m0[m bytes
 .../__pycache__/rfc6955.cpython-312.pyc            |    Bin [31m2954[m -> [32m0[m bytes
 .../__pycache__/rfc6960.cpython-312.pyc            |    Bin [31m12698[m -> [32m0[m bytes
 .../__pycache__/rfc7030.cpython-312.pyc            |    Bin [31m1861[m -> [32m0[m bytes
 .../__pycache__/rfc7191.cpython-312.pyc            |    Bin [31m9629[m -> [32m0[m bytes
 .../__pycache__/rfc7229.cpython-312.pyc            |    Bin [31m762[m -> [32m0[m bytes
 .../__pycache__/rfc7292.cpython-312.pyc            |    Bin [31m11675[m -> [32m0[m bytes
 .../__pycache__/rfc7296.cpython-312.pyc            |    Bin [31m1494[m -> [32m0[m bytes
 .../__pycache__/rfc7508.cpython-312.pyc            |    Bin [31m3472[m -> [32m0[m bytes
 .../__pycache__/rfc7585.cpython-312.pyc            |    Bin [31m1206[m -> [32m0[m bytes
 .../__pycache__/rfc7633.cpython-312.pyc            |    Bin [31m876[m -> [32m0[m bytes
 .../__pycache__/rfc7773.cpython-312.pyc            |    Bin [31m1678[m -> [32m0[m bytes
 .../__pycache__/rfc7894.cpython-312.pyc            |    Bin [31m3151[m -> [32m0[m bytes
 .../__pycache__/rfc7906.cpython-312.pyc            |    Bin [31m25421[m -> [32m0[m bytes
 .../__pycache__/rfc7914.cpython-312.pyc            |    Bin [31m2016[m -> [32m0[m bytes
 .../__pycache__/rfc8017.cpython-312.pyc            |    Bin [31m5945[m -> [32m0[m bytes
 .../__pycache__/rfc8018.cpython-312.pyc            |    Bin [31m8480[m -> [32m0[m bytes
 .../__pycache__/rfc8103.cpython-312.pyc            |    Bin [31m1235[m -> [32m0[m bytes
 .../__pycache__/rfc8209.cpython-312.pyc            |    Bin [31m367[m -> [32m0[m bytes
 .../__pycache__/rfc8226.cpython-312.pyc            |    Bin [31m6523[m -> [32m0[m bytes
 .../__pycache__/rfc8358.cpython-312.pyc            |    Bin [31m1197[m -> [32m0[m bytes
 .../__pycache__/rfc8360.cpython-312.pyc            |    Bin [31m821[m -> [32m0[m bytes
 .../__pycache__/rfc8398.cpython-312.pyc            |    Bin [31m1147[m -> [32m0[m bytes
 .../__pycache__/rfc8410.cpython-312.pyc            |    Bin [31m1425[m -> [32m0[m bytes
 .../__pycache__/rfc8418.cpython-312.pyc            |    Bin [31m1444[m -> [32m0[m bytes
 .../__pycache__/rfc8419.cpython-312.pyc            |    Bin [31m1571[m -> [32m0[m bytes
 .../__pycache__/rfc8479.cpython-312.pyc            |    Bin [31m1320[m -> [32m0[m bytes
 .../__pycache__/rfc8494.cpython-312.pyc            |    Bin [31m3653[m -> [32m0[m bytes
 .../__pycache__/rfc8520.cpython-312.pyc            |    Bin [31m1425[m -> [32m0[m bytes
 .../__pycache__/rfc8619.cpython-312.pyc            |    Bin [31m938[m -> [32m0[m bytes
 .../__pycache__/rfc8649.cpython-312.pyc            |    Bin [31m1166[m -> [32m0[m bytes
 .../__pycache__/rfc8692.cpython-312.pyc            |    Bin [31m1763[m -> [32m0[m bytes
 .../__pycache__/rfc8696.cpython-312.pyc            |    Bin [31m5227[m -> [32m0[m bytes
 .../__pycache__/rfc8702.cpython-312.pyc            |    Bin [31m3046[m -> [32m0[m bytes
 .../__pycache__/rfc8708.cpython-312.pyc            |    Bin [31m900[m -> [32m0[m bytes
 .../__pycache__/rfc8769.cpython-312.pyc            |    Bin [31m441[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pyasn1_modules/pem.py   |     58 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc1155.py    |     96 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc1157.py    |    126 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc1901.py    |     22 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc1902.py    |    129 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc1905.py    |    135 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2251.py    |    563 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2314.py    |     48 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2315.py    |    294 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2437.py    |     69 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2459.py    |   1339 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2511.py    |    258 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2560.py    |    225 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2631.py    |     37 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2634.py    |    336 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2876.py    |     56 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2985.py    |    588 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc2986.py    |     75 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3058.py    |     42 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3114.py    |     77 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3125.py    |    469 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3161.py    |    142 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3274.py    |     59 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3279.py    |    260 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3280.py    |   1543 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3281.py    |    331 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3370.py    |    146 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3412.py    |     53 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3414.py    |     28 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3447.py    |     45 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3537.py    |     34 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3560.py    |     74 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3565.py    |     57 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3657.py    |     66 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3709.py    |    207 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3739.py    |    203 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3770.py    |     75 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3779.py    |    137 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3820.py    |     65 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc3852.py    |    706 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4010.py    |     58 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4043.py    |     43 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4055.py    |    258 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4073.py    |     59 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4108.py    |    350 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4210.py    |    803 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4211.py    |    396 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4334.py    |     75 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4357.py    |    477 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4387.py    |     23 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4476.py    |     93 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4490.py    |    113 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4491.py    |     44 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4683.py    |     72 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc4985.py    |     49 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5035.py    |    199 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5083.py    |     52 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5084.py    |     97 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5126.py    |    577 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5208.py    |     56 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5275.py    |    404 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5280.py    |   1658 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5480.py    |    190 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5636.py    |    113 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5639.py    |     49 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5649.py    |     33 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5652.py    |    761 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5697.py    |     70 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5751.py    |    124 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5752.py    |     49 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5753.py    |    157 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5755.py    |    398 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5913.py    |     44 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5914.py    |    119 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5915.py    |     32 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5916.py    |     35 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5917.py    |     55 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5924.py    |     19 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5934.py    |    786 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5940.py    |     59 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5958.py    |     98 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc5990.py    |    237 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6010.py    |     88 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6019.py    |     45 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6031.py    |    469 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6032.py    |     68 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6120.py    |     43 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6170.py    |     17 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6187.py    |     22 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6210.py    |     42 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6211.py    |     72 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6402.py    |    628 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6482.py    |     74 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6486.py    |     68 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6487.py    |     22 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6664.py    |    147 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6955.py    |    108 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc6960.py    |    223 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7030.py    |     66 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7191.py    |    261 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7229.py    |     29 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7292.py    |    357 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7296.py    |     32 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7508.py    |     90 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7585.py    |     50 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7633.py    |     38 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7773.py    |     52 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7894.py    |     92 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7906.py    |    736 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc7914.py    |     49 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8017.py    |    153 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8018.py    |    260 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8103.py    |     36 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8209.py    |     20 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8226.py    |    149 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8358.py    |     50 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8360.py    |     44 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8398.py    |     52 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8410.py    |     43 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8418.py    |     36 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8419.py    |     68 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8479.py    |     45 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8494.py    |     80 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8520.py    |     63 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8619.py    |     45 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8649.py    |     40 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8692.py    |     79 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8696.py    |    104 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8702.py    |    105 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8708.py    |     41 [31m-[m
 .../Lib/site-packages/pyasn1_modules/rfc8769.py    |     21 [31m-[m
 .../pycparser-2.23.dist-info/INSTALLER             |      1 [31m-[m
 .../site-packages/pycparser-2.23.dist-info/LICENSE |     27 [31m-[m
 .../pycparser-2.23.dist-info/METADATA              |     28 [31m-[m
 .../site-packages/pycparser-2.23.dist-info/RECORD  |     41 [31m-[m
 .../site-packages/pycparser-2.23.dist-info/WHEEL   |      5 [31m-[m
 .../pycparser-2.23.dist-info/top_level.txt         |      1 [31m-[m
 .../venv/Lib/site-packages/pycparser/__init__.py   |     93 [31m-[m
 .../pycparser/__pycache__/__init__.cpython-312.pyc |    Bin [31m3023[m -> [32m0[m bytes
 .../pycparser/__pycache__/_ast_gen.cpython-312.pyc |    Bin [31m12476[m -> [32m0[m bytes
 .../__pycache__/_build_tables.cpython-312.pyc      |    Bin [31m773[m -> [32m0[m bytes
 .../__pycache__/ast_transforms.cpython-312.pyc     |    Bin [31m5548[m -> [32m0[m bytes
 .../pycparser/__pycache__/c_ast.cpython-312.pyc    |    Bin [31m50179[m -> [32m0[m bytes
 .../__pycache__/c_generator.cpython-312.pyc        |    Bin [31m30057[m -> [32m0[m bytes
 .../pycparser/__pycache__/c_lexer.cpython-312.pyc  |    Bin [31m18253[m -> [32m0[m bytes
 .../pycparser/__pycache__/c_parser.cpython-312.pyc |    Bin [31m88344[m -> [32m0[m bytes
 .../pycparser/__pycache__/lextab.cpython-312.pyc   |    Bin [31m6964[m -> [32m0[m bytes
 .../__pycache__/plyparser.cpython-312.pyc          |    Bin [31m6038[m -> [32m0[m bytes
 .../pycparser/__pycache__/yacctab.cpython-312.pyc  |    Bin [31m192156[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pycparser/_ast_gen.py   |    336 [31m-[m
 .../Lib/site-packages/pycparser/_build_tables.py   |     40 [31m-[m
 .../venv/Lib/site-packages/pycparser/_c_ast.cfg    |    195 [31m-[m
 .../Lib/site-packages/pycparser/ast_transforms.py  |    164 [31m-[m
 backend/venv/Lib/site-packages/pycparser/c_ast.py  |   1125 [31m-[m
 .../Lib/site-packages/pycparser/c_generator.py     |    502 [31m-[m
 .../venv/Lib/site-packages/pycparser/c_lexer.py    |    569 [31m-[m
 .../venv/Lib/site-packages/pycparser/c_parser.py   |   1973 [31m-[m
 backend/venv/Lib/site-packages/pycparser/lextab.py |     10 [31m-[m
 .../Lib/site-packages/pycparser/ply/__init__.py    |      5 [31m-[m
 .../ply/__pycache__/__init__.cpython-312.pyc       |    Bin [31m238[m -> [32m0[m bytes
 .../pycparser/ply/__pycache__/cpp.cpython-312.pyc  |    Bin [31m32242[m -> [32m0[m bytes
 .../ply/__pycache__/ctokens.cpython-312.pyc        |    Bin [31m2450[m -> [32m0[m bytes
 .../pycparser/ply/__pycache__/lex.cpython-312.pyc  |    Bin [31m41353[m -> [32m0[m bytes
 .../pycparser/ply/__pycache__/yacc.cpython-312.pyc |    Bin [31m100585[m -> [32m0[m bytes
 .../pycparser/ply/__pycache__/ygen.cpython-312.pyc |    Bin [31m2963[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pycparser/ply/cpp.py    |    905 [31m-[m
 .../Lib/site-packages/pycparser/ply/ctokens.py     |    133 [31m-[m
 .../venv/Lib/site-packages/pycparser/ply/lex.py    |   1099 [31m-[m
 .../venv/Lib/site-packages/pycparser/ply/yacc.py   |   3494 [31m-[m
 .../venv/Lib/site-packages/pycparser/ply/ygen.py   |     74 [31m-[m
 .../venv/Lib/site-packages/pycparser/plyparser.py  |    133 [31m-[m
 .../venv/Lib/site-packages/pycparser/yacctab.py    |    374 [31m-[m
 .../pydantic-2.12.5.dist-info/INSTALLER            |      1 [31m-[m
 .../pydantic-2.12.5.dist-info/METADATA             |   1029 [31m-[m
 .../site-packages/pydantic-2.12.5.dist-info/RECORD |    218 [31m-[m
 .../pydantic-2.12.5.dist-info/REQUESTED            |      0
 .../site-packages/pydantic-2.12.5.dist-info/WHEEL  |      4 [31m-[m
 .../pydantic-2.12.5.dist-info/licenses/LICENSE     |     21 [31m-[m
 .../venv/Lib/site-packages/pydantic/__init__.py    |    456 [31m-[m
 .../pydantic/__pycache__/__init__.cpython-312.pyc  |    Bin [31m14410[m -> [32m0[m bytes
 .../__pycache__/_migration.cpython-312.pyc         |    Bin [31m11017[m -> [32m0[m bytes
 .../__pycache__/alias_generators.cpython-312.pyc   |    Bin [31m3267[m -> [32m0[m bytes
 .../pydantic/__pycache__/aliases.cpython-312.pyc   |    Bin [31m6547[m -> [32m0[m bytes
 .../__pycache__/annotated_handlers.cpython-312.pyc |    Bin [31m5481[m -> [32m0[m bytes
 .../__pycache__/class_validators.cpython-312.pyc   |    Bin [31m355[m -> [32m0[m bytes
 .../pydantic/__pycache__/color.cpython-312.pyc     |    Bin [31m30161[m -> [32m0[m bytes
 .../pydantic/__pycache__/config.cpython-312.pyc    |    Bin [31m7487[m -> [32m0[m bytes
 .../__pycache__/dataclasses.cpython-312.pyc        |    Bin [31m17314[m -> [32m0[m bytes
 .../__pycache__/datetime_parse.cpython-312.pyc     |    Bin [31m355[m -> [32m0[m bytes
 .../pydantic/__pycache__/decorator.cpython-312.pyc |    Bin [31m345[m -> [32m0[m bytes
 .../__pycache__/env_settings.cpython-312.pyc       |    Bin [31m351[m -> [32m0[m bytes
 .../__pycache__/error_wrappers.cpython-312.pyc     |    Bin [31m355[m -> [32m0[m bytes
 .../pydantic/__pycache__/errors.cpython-312.pyc    |    Bin [31m7616[m -> [32m0[m bytes
 .../pydantic/__pycache__/fields.cpython-312.pyc    |    Bin [31m72912[m -> [32m0[m bytes
 .../functional_serializers.cpython-312.pyc         |    Bin [31m17918[m -> [32m0[m bytes
 .../functional_validators.cpython-312.pyc          |    Bin [31m34729[m -> [32m0[m bytes
 .../pydantic/__pycache__/generics.cpython-312.pyc  |    Bin [31m343[m -> [32m0[m bytes
 .../pydantic/__pycache__/json.cpython-312.pyc      |    Bin [31m335[m -> [32m0[m bytes
 .../__pycache__/json_schema.cpython-312.pyc        |    Bin [31m119998[m -> [32m0[m bytes
 .../pydantic/__pycache__/main.cpython-312.pyc      |    Bin [31m77289[m -> [32m0[m bytes
 .../pydantic/__pycache__/mypy.cpython-312.pyc      |    Bin [31m61624[m -> [32m0[m bytes
 .../pydantic/__pycache__/networks.cpython-312.pyc  |    Bin [31m50204[m -> [32m0[m bytes
 .../pydantic/__pycache__/parse.cpython-312.pyc     |    Bin [31m337[m -> [32m0[m bytes
 .../__pycache__/root_model.cpython-312.pyc         |    Bin [31m7798[m -> [32m0[m bytes
 .../pydantic/__pycache__/schema.cpython-312.pyc    |    Bin [31m339[m -> [32m0[m bytes
 .../pydantic/__pycache__/tools.cpython-312.pyc     |    Bin [31m337[m -> [32m0[m bytes
 .../__pycache__/type_adapter.cpython-312.pyc       |    Bin [31m35534[m -> [32m0[m bytes
 .../pydantic/__pycache__/types.cpython-312.pyc     |    Bin [31m96755[m -> [32m0[m bytes
 .../pydantic/__pycache__/typing.cpython-312.pyc    |    Bin [31m335[m -> [32m0[m bytes
 .../pydantic/__pycache__/utils.cpython-312.pyc     |    Bin [31m337[m -> [32m0[m bytes
 .../validate_call_decorator.cpython-312.pyc        |    Bin [31m5433[m -> [32m0[m bytes
 .../__pycache__/validators.cpython-312.pyc         |    Bin [31m347[m -> [32m0[m bytes
 .../pydantic/__pycache__/version.cpython-312.pyc   |    Bin [31m4783[m -> [32m0[m bytes
 .../pydantic/__pycache__/warnings.cpython-312.pyc  |    Bin [31m7199[m -> [32m0[m bytes
 .../site-packages/pydantic/_internal/__init__.py   |      0
 .../_internal/__pycache__/__init__.cpython-312.pyc |    Bin [31m180[m -> [32m0[m bytes
 .../_internal/__pycache__/_config.cpython-312.pyc  |    Bin [31m15659[m -> [32m0[m bytes
 .../__pycache__/_core_metadata.cpython-312.pyc     |    Bin [31m4600[m -> [32m0[m bytes
 .../__pycache__/_core_utils.cpython-312.pyc        |    Bin [31m7697[m -> [32m0[m bytes
 .../__pycache__/_dataclasses.cpython-312.pyc       |    Bin [31m13388[m -> [32m0[m bytes
 .../__pycache__/_decorators.cpython-312.pyc        |    Bin [31m36743[m -> [32m0[m bytes
 .../__pycache__/_decorators_v1.cpython-312.pyc     |    Bin [31m8600[m -> [32m0[m bytes
 .../_discriminated_union.cpython-312.pyc           |    Bin [31m20831[m -> [32m0[m bytes
 .../__pycache__/_docs_extraction.cpython-312.pyc   |    Bin [31m5293[m -> [32m0[m bytes
 .../_internal/__pycache__/_fields.cpython-312.pyc  |    Bin [31m24275[m -> [32m0[m bytes
 .../__pycache__/_forward_ref.cpython-312.pyc       |    Bin [31m1289[m -> [32m0[m bytes
 .../__pycache__/_generate_schema.cpython-312.pyc   |    Bin [31m130316[m -> [32m0[m bytes
 .../__pycache__/_generics.cpython-312.pyc          |    Bin [31m24316[m -> [32m0[m bytes
 .../_internal/__pycache__/_git.cpython-312.pyc     |    Bin [31m1495[m -> [32m0[m bytes
 .../__pycache__/_import_utils.cpython-312.pyc      |    Bin [31m808[m -> [32m0[m bytes
 .../_internal_dataclass.cpython-312.pyc            |    Bin [31m329[m -> [32m0[m bytes
 .../_known_annotated_metadata.cpython-312.pyc      |    Bin [31m14211[m -> [32m0[m bytes
 .../__pycache__/_mock_val_ser.cpython-312.pyc      |    Bin [31m11078[m -> [32m0[m bytes
 .../_model_construction.cpython-312.pyc            |    Bin [31m35090[m -> [32m0[m bytes
 .../__pycache__/_namespace_utils.cpython-312.pyc   |    Bin [31m12298[m -> [32m0[m bytes
 .../_internal/__pycache__/_repr.cpython-312.pyc    |    Bin [31m7838[m -> [32m0[m bytes
 .../__pycache__/_schema_gather.cpython-312.pyc     |    Bin [31m7625[m -> [32m0[m bytes
 .../_schema_generation_shared.cpython-312.pyc      |    Bin [31m6206[m -> [32m0[m bytes
 .../__pycache__/_serializers.cpython-312.pyc       |    Bin [31m2096[m -> [32m0[m bytes
 .../__pycache__/_signature.cpython-312.pyc         |    Bin [31m6746[m -> [32m0[m bytes
 .../__pycache__/_typing_extra.cpython-312.pyc      |    Bin [31m28165[m -> [32m0[m bytes
 .../_internal/__pycache__/_utils.cpython-312.pyc   |    Bin [31m19753[m -> [32m0[m bytes
 .../__pycache__/_validate_call.cpython-312.pyc     |    Bin [31m6967[m -> [32m0[m bytes
 .../__pycache__/_validators.cpython-312.pyc        |    Bin [31m22946[m -> [32m0[m bytes
 .../site-packages/pydantic/_internal/_config.py    |    383 [31m-[m
 .../pydantic/_internal/_core_metadata.py           |     97 [31m-[m
 .../pydantic/_internal/_core_utils.py              |    174 [31m-[m
 .../pydantic/_internal/_dataclasses.py             |    315 [31m-[m
 .../pydantic/_internal/_decorators.py              |    858 [31m-[m
 .../pydantic/_internal/_decorators_v1.py           |    174 [31m-[m
 .../pydantic/_internal/_discriminated_union.py     |    479 [31m-[m
 .../pydantic/_internal/_docs_extraction.py         |    113 [31m-[m
 .../site-packages/pydantic/_internal/_fields.py    |    635 [31m-[m
 .../pydantic/_internal/_forward_ref.py             |     23 [31m-[m
 .../pydantic/_internal/_generate_schema.py         |   2867 [31m-[m
 .../site-packages/pydantic/_internal/_generics.py  |    543 [31m-[m
 .../Lib/site-packages/pydantic/_internal/_git.py   |     27 [31m-[m
 .../pydantic/_internal/_import_utils.py            |     20 [31m-[m
 .../pydantic/_internal/_internal_dataclass.py      |      7 [31m-[m
 .../_internal/_known_annotated_metadata.py         |    401 [31m-[m
 .../pydantic/_internal/_mock_val_ser.py            |    228 [31m-[m
 .../pydantic/_internal/_model_construction.py      |    848 [31m-[m
 .../pydantic/_internal/_namespace_utils.py         |    293 [31m-[m
 .../Lib/site-packages/pydantic/_internal/_repr.py  |    124 [31m-[m
 .../pydantic/_internal/_schema_gather.py           |    209 [31m-[m
 .../_internal/_schema_generation_shared.py         |    125 [31m-[m
 .../pydantic/_internal/_serializers.py             |     53 [31m-[m
 .../site-packages/pydantic/_internal/_signature.py |    188 [31m-[m
 .../pydantic/_internal/_typing_extra.py            |    760 [31m-[m
 .../Lib/site-packages/pydantic/_internal/_utils.py |    446 [31m-[m
 .../pydantic/_internal/_validate_call.py           |    140 [31m-[m
 .../pydantic/_internal/_validators.py              |    533 [31m-[m
 .../venv/Lib/site-packages/pydantic/_migration.py  |    316 [31m-[m
 .../Lib/site-packages/pydantic/alias_generators.py |     62 [31m-[m
 backend/venv/Lib/site-packages/pydantic/aliases.py |    135 [31m-[m
 .../site-packages/pydantic/annotated_handlers.py   |    122 [31m-[m
 .../Lib/site-packages/pydantic/class_validators.py |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/color.py   |    604 [31m-[m
 backend/venv/Lib/site-packages/pydantic/config.py  |   1288 [31m-[m
 .../venv/Lib/site-packages/pydantic/dataclasses.py |    413 [31m-[m
 .../Lib/site-packages/pydantic/datetime_parse.py   |      5 [31m-[m
 .../venv/Lib/site-packages/pydantic/decorator.py   |      5 [31m-[m
 .../site-packages/pydantic/deprecated/__init__.py  |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m181[m -> [32m0[m bytes
 .../__pycache__/class_validators.cpython-312.pyc   |    Bin [31m11739[m -> [32m0[m bytes
 .../deprecated/__pycache__/config.cpython-312.pyc  |    Bin [31m4058[m -> [32m0[m bytes
 .../__pycache__/copy_internals.cpython-312.pyc     |    Bin [31m8645[m -> [32m0[m bytes
 .../__pycache__/decorator.cpython-312.pyc          |    Bin [31m14009[m -> [32m0[m bytes
 .../deprecated/__pycache__/json.cpython-312.pyc    |    Bin [31m6157[m -> [32m0[m bytes
 .../deprecated/__pycache__/parse.cpython-312.pyc   |    Bin [31m3387[m -> [32m0[m bytes
 .../deprecated/__pycache__/tools.cpython-312.pyc   |    Bin [31m3523[m -> [32m0[m bytes
 .../pydantic/deprecated/class_validators.py        |    256 [31m-[m
 .../site-packages/pydantic/deprecated/config.py    |     72 [31m-[m
 .../pydantic/deprecated/copy_internals.py          |    224 [31m-[m
 .../site-packages/pydantic/deprecated/decorator.py |    284 [31m-[m
 .../Lib/site-packages/pydantic/deprecated/json.py  |    141 [31m-[m
 .../Lib/site-packages/pydantic/deprecated/parse.py |     80 [31m-[m
 .../Lib/site-packages/pydantic/deprecated/tools.py |    103 [31m-[m
 .../Lib/site-packages/pydantic/env_settings.py     |      5 [31m-[m
 .../Lib/site-packages/pydantic/error_wrappers.py   |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/errors.py  |    189 [31m-[m
 .../pydantic/experimental/__init__.py              |      1 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m295[m -> [32m0[m bytes
 .../__pycache__/arguments_schema.cpython-312.pyc   |    Bin [31m2387[m -> [32m0[m bytes
 .../__pycache__/missing_sentinel.cpython-312.pyc   |    Bin [31m336[m -> [32m0[m bytes
 .../__pycache__/pipeline.cpython-312.pyc           |    Bin [31m34444[m -> [32m0[m bytes
 .../pydantic/experimental/arguments_schema.py      |     44 [31m-[m
 .../pydantic/experimental/missing_sentinel.py      |      5 [31m-[m
 .../pydantic/experimental/pipeline.py              |    654 [31m-[m
 backend/venv/Lib/site-packages/pydantic/fields.py  |   1834 [31m-[m
 .../pydantic/functional_serializers.py             |    451 [31m-[m
 .../pydantic/functional_validators.py              |    893 [31m-[m
 .../venv/Lib/site-packages/pydantic/generics.py    |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/json.py    |      5 [31m-[m
 .../venv/Lib/site-packages/pydantic/json_schema.py |   2854 [31m-[m
 backend/venv/Lib/site-packages/pydantic/main.py    |   1819 [31m-[m
 backend/venv/Lib/site-packages/pydantic/mypy.py    |   1374 [31m-[m
 .../venv/Lib/site-packages/pydantic/networks.py    |   1331 [31m-[m
 backend/venv/Lib/site-packages/pydantic/parse.py   |      5 [31m-[m
 .../Lib/site-packages/pydantic/plugin/__init__.py  |    193 [31m-[m
 .../plugin/__pycache__/__init__.cpython-312.pyc    |    Bin [31m8923[m -> [32m0[m bytes
 .../plugin/__pycache__/_loader.cpython-312.pyc     |    Bin [31m2413[m -> [32m0[m bytes
 .../__pycache__/_schema_validator.cpython-312.pyc  |    Bin [31m6901[m -> [32m0[m bytes
 .../Lib/site-packages/pydantic/plugin/_loader.py   |     58 [31m-[m
 .../pydantic/plugin/_schema_validator.py           |    140 [31m-[m
 backend/venv/Lib/site-packages/pydantic/py.typed   |      0
 .../venv/Lib/site-packages/pydantic/root_model.py  |    155 [31m-[m
 backend/venv/Lib/site-packages/pydantic/schema.py  |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/tools.py   |      5 [31m-[m
 .../Lib/site-packages/pydantic/type_adapter.py     |    795 [31m-[m
 backend/venv/Lib/site-packages/pydantic/types.py   |   3295 [31m-[m
 backend/venv/Lib/site-packages/pydantic/typing.py  |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/utils.py   |      5 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/__init__.py |    142 [31m-[m
 .../v1/__pycache__/__init__.cpython-312.pyc        |    Bin [31m2502[m -> [32m0[m bytes
 .../__pycache__/_hypothesis_plugin.cpython-312.pyc |    Bin [31m20489[m -> [32m0[m bytes
 .../v1/__pycache__/annotated_types.cpython-312.pyc |    Bin [31m3868[m -> [32m0[m bytes
 .../__pycache__/class_validators.cpython-312.pyc   |    Bin [31m19628[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/color.cpython-312.pyc  |    Bin [31m25834[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/config.cpython-312.pyc |    Bin [31m8383[m -> [32m0[m bytes
 .../v1/__pycache__/dataclasses.cpython-312.pyc     |    Bin [31m22728[m -> [32m0[m bytes
 .../v1/__pycache__/datetime_parse.cpython-312.pyc  |    Bin [31m10336[m -> [32m0[m bytes
 .../v1/__pycache__/decorator.cpython-312.pyc       |    Bin [31m13901[m -> [32m0[m bytes
 .../v1/__pycache__/env_settings.cpython-312.pyc    |    Bin [31m17703[m -> [32m0[m bytes
 .../v1/__pycache__/error_wrappers.cpython-312.pyc  |    Bin [31m8911[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/errors.cpython-312.pyc |    Bin [31m29586[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/fields.cpython-312.pyc |    Bin [31m57426[m -> [32m0[m bytes
 .../v1/__pycache__/generics.cpython-312.pyc        |    Bin [31m16976[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/json.cpython-312.pyc   |    Bin [31m5194[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/main.cpython-312.pyc   |    Bin [31m48200[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/mypy.cpython-312.pyc   |    Bin [31m46342[m -> [32m0[m bytes
 .../v1/__pycache__/networks.cpython-312.pyc        |    Bin [31m29533[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/parse.cpython-312.pyc  |    Bin [31m2731[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/schema.cpython-312.pyc |    Bin [31m48459[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/tools.cpython-312.pyc  |    Bin [31m3864[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/types.cpython-312.pyc  |    Bin [31m48471[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/typing.cpython-312.pyc |    Bin [31m22614[m -> [32m0[m bytes
 .../pydantic/v1/__pycache__/utils.cpython-312.pyc  |    Bin [31m35221[m -> [32m0[m bytes
 .../v1/__pycache__/validators.cpython-312.pyc      |    Bin [31m30879[m -> [32m0[m bytes
 .../v1/__pycache__/version.cpython-312.pyc         |    Bin [31m1942[m -> [32m0[m bytes
 .../pydantic/v1/_hypothesis_plugin.py              |    391 [31m-[m
 .../site-packages/pydantic/v1/annotated_types.py   |     72 [31m-[m
 .../site-packages/pydantic/v1/class_validators.py  |    361 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/color.py    |    494 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/config.py   |    191 [31m-[m
 .../Lib/site-packages/pydantic/v1/dataclasses.py   |    500 [31m-[m
 .../site-packages/pydantic/v1/datetime_parse.py    |    248 [31m-[m
 .../Lib/site-packages/pydantic/v1/decorator.py     |    264 [31m-[m
 .../Lib/site-packages/pydantic/v1/env_settings.py  |    350 [31m-[m
 .../site-packages/pydantic/v1/error_wrappers.py    |    161 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/errors.py   |    646 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/fields.py   |   1253 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/generics.py |    400 [31m-[m
 backend/venv/Lib/site-packages/pydantic/v1/json.py |    112 [31m-[m
 backend/venv/Lib/site-packages/pydantic/v1/main.py |   1113 [31m-[m
 backend/venv/Lib/site-packages/pydantic/v1/mypy.py |    949 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/networks.py |    747 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/parse.py    |     66 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/py.typed    |      0
 .../venv/Lib/site-packages/pydantic/v1/schema.py   |   1163 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/tools.py    |     92 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/types.py    |   1205 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/typing.py   |    614 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/utils.py    |    806 [31m-[m
 .../Lib/site-packages/pydantic/v1/validators.py    |    768 [31m-[m
 .../venv/Lib/site-packages/pydantic/v1/version.py  |     38 [31m-[m
 .../pydantic/validate_call_decorator.py            |    116 [31m-[m
 .../venv/Lib/site-packages/pydantic/validators.py  |      5 [31m-[m
 backend/venv/Lib/site-packages/pydantic/version.py |    113 [31m-[m
 .../venv/Lib/site-packages/pydantic/warnings.py    |    122 [31m-[m
 .../pydantic_core-2.41.5.dist-info/INSTALLER       |      1 [31m-[m
 .../pydantic_core-2.41.5.dist-info/METADATA        |    180 [31m-[m
 .../pydantic_core-2.41.5.dist-info/RECORD          |     12 [31m-[m
 .../pydantic_core-2.41.5.dist-info/WHEEL           |      4 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../Lib/site-packages/pydantic_core/__init__.py    |    171 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m3136[m -> [32m0[m bytes
 .../__pycache__/core_schema.cpython-312.pyc        |    Bin [31m155142[m -> [32m0[m bytes
 .../_pydantic_core.cp312-win_amd64.pyd             |    Bin [31m5436928[m -> [32m0[m bytes
 .../site-packages/pydantic_core/_pydantic_core.pyi |   1046 [31m-[m
 .../Lib/site-packages/pydantic_core/core_schema.py |   4435 [31m-[m
 .../venv/Lib/site-packages/pydantic_core/py.typed  |      0
 .../pydantic_settings-2.12.0.dist-info/INSTALLER   |      1 [31m-[m
 .../pydantic_settings-2.12.0.dist-info/METADATA    |     63 [31m-[m
 .../pydantic_settings-2.12.0.dist-info/RECORD      |     51 [31m-[m
 .../pydantic_settings-2.12.0.dist-info/REQUESTED   |      0
 .../pydantic_settings-2.12.0.dist-info/WHEEL       |      4 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../site-packages/pydantic_settings/__init__.py    |     65 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1385[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m433[m -> [32m0[m bytes
 .../__pycache__/main.cpython-312.pyc               |    Bin [31m28615[m -> [32m0[m bytes
 .../__pycache__/utils.cpython-312.pyc              |    Bin [31m1769[m -> [32m0[m bytes
 .../__pycache__/version.cpython-312.pyc            |    Bin [31m201[m -> [32m0[m bytes
 .../site-packages/pydantic_settings/exceptions.py  |      4 [31m-[m
 .../Lib/site-packages/pydantic_settings/main.py    |    717 [31m-[m
 .../Lib/site-packages/pydantic_settings/py.typed   |      0
 .../pydantic_settings/sources/__init__.py          |     70 [31m-[m
 .../sources/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1915[m -> [32m0[m bytes
 .../sources/__pycache__/base.cpython-312.pyc       |    Bin [31m24685[m -> [32m0[m bytes
 .../sources/__pycache__/types.cpython-312.pyc      |    Bin [31m2316[m -> [32m0[m bytes
 .../sources/__pycache__/utils.cpython-312.pyc      |    Bin [31m10280[m -> [32m0[m bytes
 .../pydantic_settings/sources/base.py              |    541 [31m-[m
 .../sources/providers/__init__.py                  |     41 [31m-[m
 .../providers/__pycache__/__init__.cpython-312.pyc |    Bin [31m1164[m -> [32m0[m bytes
 .../providers/__pycache__/aws.cpython-312.pyc      |    Bin [31m3284[m -> [32m0[m bytes
 .../providers/__pycache__/azure.cpython-312.pyc    |    Bin [31m7548[m -> [32m0[m bytes
 .../providers/__pycache__/cli.cpython-312.pyc      |    Bin [31m70021[m -> [32m0[m bytes
 .../providers/__pycache__/dotenv.cpython-312.pyc   |    Bin [31m6908[m -> [32m0[m bytes
 .../providers/__pycache__/env.cpython-312.pyc      |    Bin [31m12476[m -> [32m0[m bytes
 .../providers/__pycache__/gcp.cpython-312.pyc      |    Bin [31m7127[m -> [32m0[m bytes
 .../providers/__pycache__/json.cpython-312.pyc     |    Bin [31m2463[m -> [32m0[m bytes
 .../__pycache__/nested_secrets.cpython-312.pyc     |    Bin [31m7935[m -> [32m0[m bytes
 .../__pycache__/pyproject.cpython-312.pyc          |    Bin [31m3028[m -> [32m0[m bytes
 .../providers/__pycache__/secrets.cpython-312.pyc  |    Bin [31m5757[m -> [32m0[m bytes
 .../providers/__pycache__/toml.cpython-312.pyc     |    Bin [31m3026[m -> [32m0[m bytes
 .../providers/__pycache__/yaml.cpython-312.pyc     |    Bin [31m3408[m -> [32m0[m bytes
 .../pydantic_settings/sources/providers/aws.py     |     79 [31m-[m
 .../pydantic_settings/sources/providers/azure.py   |    145 [31m-[m
 .../pydantic_settings/sources/providers/cli.py     |   1357 [31m-[m
 .../pydantic_settings/sources/providers/dotenv.py  |    168 [31m-[m
 .../pydantic_settings/sources/providers/env.py     |    294 [31m-[m
 .../pydantic_settings/sources/providers/gcp.py     |    152 [31m-[m
 .../pydantic_settings/sources/providers/json.py    |     47 [31m-[m
 .../sources/providers/nested_secrets.py            |    166 [31m-[m
 .../sources/providers/pyproject.py                 |     62 [31m-[m
 .../pydantic_settings/sources/providers/secrets.py |    125 [31m-[m
 .../pydantic_settings/sources/providers/toml.py    |     66 [31m-[m
 .../pydantic_settings/sources/providers/yaml.py    |     75 [31m-[m
 .../pydantic_settings/sources/types.py             |     78 [31m-[m
 .../pydantic_settings/sources/utils.py             |    214 [31m-[m
 .../Lib/site-packages/pydantic_settings/utils.py   |     42 [31m-[m
 .../Lib/site-packages/pydantic_settings/version.py |      1 [31m-[m
 .../pygments-2.19.2.dist-info/INSTALLER            |      1 [31m-[m
 .../pygments-2.19.2.dist-info/METADATA             |     58 [31m-[m
 .../site-packages/pygments-2.19.2.dist-info/RECORD |    684 [31m-[m
 .../site-packages/pygments-2.19.2.dist-info/WHEEL  |      4 [31m-[m
 .../pygments-2.19.2.dist-info/entry_points.txt     |      2 [31m-[m
 .../pygments-2.19.2.dist-info/licenses/AUTHORS     |    291 [31m-[m
 .../pygments-2.19.2.dist-info/licenses/LICENSE     |     25 [31m-[m
 .../venv/Lib/site-packages/pygments/__init__.py    |     82 [31m-[m
 .../venv/Lib/site-packages/pygments/__main__.py    |     17 [31m-[m
 .../pygments/__pycache__/__init__.cpython-312.pyc  |    Bin [31m3443[m -> [32m0[m bytes
 .../pygments/__pycache__/__main__.cpython-312.pyc  |    Bin [31m762[m -> [32m0[m bytes
 .../pygments/__pycache__/cmdline.cpython-312.pyc   |    Bin [31m26443[m -> [32m0[m bytes
 .../pygments/__pycache__/console.cpython-312.pyc   |    Bin [31m2607[m -> [32m0[m bytes
 .../pygments/__pycache__/filter.cpython-312.pyc    |    Bin [31m3200[m -> [32m0[m bytes
 .../pygments/__pycache__/formatter.cpython-312.pyc |    Bin [31m4675[m -> [32m0[m bytes
 .../pygments/__pycache__/lexer.cpython-312.pyc     |    Bin [31m38630[m -> [32m0[m bytes
 .../pygments/__pycache__/modeline.cpython-312.pyc  |    Bin [31m1538[m -> [32m0[m bytes
 .../pygments/__pycache__/plugin.cpython-312.pyc    |    Bin [31m2587[m -> [32m0[m bytes
 .../pygments/__pycache__/regexopt.cpython-312.pyc  |    Bin [31m4056[m -> [32m0[m bytes
 .../pygments/__pycache__/scanner.cpython-312.pyc   |    Bin [31m4735[m -> [32m0[m bytes
 .../pygments/__pycache__/sphinxext.cpython-312.pyc |    Bin [31m12047[m -> [32m0[m bytes
 .../pygments/__pycache__/style.cpython-312.pyc     |    Bin [31m6660[m -> [32m0[m bytes
 .../pygments/__pycache__/token.cpython-312.pyc     |    Bin [31m8168[m -> [32m0[m bytes
 .../pygments/__pycache__/unistring.cpython-312.pyc |    Bin [31m32951[m -> [32m0[m bytes
 .../pygments/__pycache__/util.cpython-312.pyc      |    Bin [31m14048[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pygments/cmdline.py |    668 [31m-[m
 backend/venv/Lib/site-packages/pygments/console.py |     70 [31m-[m
 backend/venv/Lib/site-packages/pygments/filter.py  |     70 [31m-[m
 .../Lib/site-packages/pygments/filters/__init__.py |    940 [31m-[m
 .../filters/__pycache__/__init__.cpython-312.pyc   |    Bin [31m37842[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pygments/formatter.py   |    129 [31m-[m
 .../site-packages/pygments/formatters/__init__.py  |    157 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m6845[m -> [32m0[m bytes
 .../__pycache__/_mapping.cpython-312.pyc           |    Bin [31m4194[m -> [32m0[m bytes
 .../formatters/__pycache__/bbcode.cpython-312.pyc  |    Bin [31m4177[m -> [32m0[m bytes
 .../formatters/__pycache__/groff.cpython-312.pyc   |    Bin [31m7248[m -> [32m0[m bytes
 .../formatters/__pycache__/html.cpython-312.pyc    |    Bin [31m41285[m -> [32m0[m bytes
 .../formatters/__pycache__/img.cpython-312.pyc     |    Bin [31m28556[m -> [32m0[m bytes
 .../formatters/__pycache__/irc.cpython-312.pyc     |    Bin [31m5998[m -> [32m0[m bytes
 .../formatters/__pycache__/latex.cpython-312.pyc   |    Bin [31m20056[m -> [32m0[m bytes
 .../formatters/__pycache__/other.cpython-312.pyc   |    Bin [31m6808[m -> [32m0[m bytes
 .../__pycache__/pangomarkup.cpython-312.pyc        |    Bin [31m2925[m -> [32m0[m bytes
 .../formatters/__pycache__/rtf.cpython-312.pyc     |    Bin [31m13716[m -> [32m0[m bytes
 .../formatters/__pycache__/svg.cpython-312.pyc     |    Bin [31m9082[m -> [32m0[m bytes
 .../__pycache__/terminal.cpython-312.pyc           |    Bin [31m5750[m -> [32m0[m bytes
 .../__pycache__/terminal256.cpython-312.pyc        |    Bin [31m15061[m -> [32m0[m bytes
 .../site-packages/pygments/formatters/_mapping.py  |     23 [31m-[m
 .../site-packages/pygments/formatters/bbcode.py    |    108 [31m-[m
 .../Lib/site-packages/pygments/formatters/groff.py |    170 [31m-[m
 .../Lib/site-packages/pygments/formatters/html.py  |    995 [31m-[m
 .../Lib/site-packages/pygments/formatters/img.py   |    686 [31m-[m
 .../Lib/site-packages/pygments/formatters/irc.py   |    154 [31m-[m
 .../Lib/site-packages/pygments/formatters/latex.py |    518 [31m-[m
 .../Lib/site-packages/pygments/formatters/other.py |    160 [31m-[m
 .../pygments/formatters/pangomarkup.py             |     83 [31m-[m
 .../Lib/site-packages/pygments/formatters/rtf.py   |    349 [31m-[m
 .../Lib/site-packages/pygments/formatters/svg.py   |    185 [31m-[m
 .../site-packages/pygments/formatters/terminal.py  |    127 [31m-[m
 .../pygments/formatters/terminal256.py             |    338 [31m-[m
 backend/venv/Lib/site-packages/pygments/lexer.py   |    961 [31m-[m
 .../Lib/site-packages/pygments/lexers/__init__.py  |    362 [31m-[m
 .../lexers/__pycache__/__init__.cpython-312.pyc    |    Bin [31m14552[m -> [32m0[m bytes
 .../__pycache__/_ada_builtins.cpython-312.pyc      |    Bin [31m1224[m -> [32m0[m bytes
 .../__pycache__/_asy_builtins.cpython-312.pyc      |    Bin [31m17617[m -> [32m0[m bytes
 .../__pycache__/_cl_builtins.cpython-312.pyc       |    Bin [31m11653[m -> [32m0[m bytes
 .../__pycache__/_cocoa_builtins.cpython-312.pyc    |    Bin [31m97515[m -> [32m0[m bytes
 .../__pycache__/_csound_builtins.cpython-312.pyc   |    Bin [31m16365[m -> [32m0[m bytes
 .../__pycache__/_css_builtins.cpython-312.pyc      |    Bin [31m9374[m -> [32m0[m bytes
 .../_googlesql_builtins.cpython-312.pyc            |    Bin [31m10812[m -> [32m0[m bytes
 .../__pycache__/_julia_builtins.cpython-312.pyc    |    Bin [31m8239[m -> [32m0[m bytes
 .../__pycache__/_lasso_builtins.cpython-312.pyc    |    Bin [31m76717[m -> [32m0[m bytes
 .../__pycache__/_lilypond_builtins.cpython-312.pyc |    Bin [31m88395[m -> [32m0[m bytes
 .../__pycache__/_lua_builtins.cpython-312.pyc      |    Bin [31m8334[m -> [32m0[m bytes
 .../__pycache__/_luau_builtins.cpython-312.pyc     |    Bin [31m1038[m -> [32m0[m bytes
 .../lexers/__pycache__/_mapping.cpython-312.pyc    |    Bin [31m66940[m -> [32m0[m bytes
 .../__pycache__/_mql_builtins.cpython-312.pyc      |    Bin [31m17998[m -> [32m0[m bytes
 .../__pycache__/_mysql_builtins.cpython-312.pyc    |    Bin [31m19514[m -> [32m0[m bytes
 .../__pycache__/_openedge_builtins.cpython-312.pyc |    Bin [31m34080[m -> [32m0[m bytes
 .../__pycache__/_php_builtins.cpython-312.pyc      |    Bin [31m65467[m -> [32m0[m bytes
 .../__pycache__/_postgres_builtins.cpython-312.pyc |    Bin [31m11235[m -> [32m0[m bytes
 .../__pycache__/_qlik_builtins.cpython-312.pyc     |    Bin [31m6365[m -> [32m0[m bytes
 .../__pycache__/_scheme_builtins.cpython-312.pyc   |    Bin [31m23162[m -> [32m0[m bytes
 .../__pycache__/_scilab_builtins.cpython-312.pyc   |    Bin [31m35183[m -> [32m0[m bytes
 .../_sourcemod_builtins.cpython-312.pyc            |    Bin [31m21796[m -> [32m0[m bytes
 .../__pycache__/_sql_builtins.cpython-312.pyc      |    Bin [31m5556[m -> [32m0[m bytes
 .../__pycache__/_stan_builtins.cpython-312.pyc     |    Bin [31m9941[m -> [32m0[m bytes
 .../__pycache__/_stata_builtins.cpython-312.pyc    |    Bin [31m21225[m -> [32m0[m bytes
 .../__pycache__/_tsql_builtins.cpython-312.pyc     |    Bin [31m8857[m -> [32m0[m bytes
 .../__pycache__/_usd_builtins.cpython-312.pyc      |    Bin [31m1387[m -> [32m0[m bytes
 .../__pycache__/_vbscript_builtins.cpython-312.pyc |    Bin [31m2916[m -> [32m0[m bytes
 .../__pycache__/_vim_builtins.cpython-312.pyc      |    Bin [31m30719[m -> [32m0[m bytes
 .../__pycache__/actionscript.cpython-312.pyc       |    Bin [31m11104[m -> [32m0[m bytes
 .../lexers/__pycache__/ada.cpython-312.pyc         |    Bin [31m5500[m -> [32m0[m bytes
 .../lexers/__pycache__/agile.cpython-312.pyc       |    Bin [31m1295[m -> [32m0[m bytes
 .../lexers/__pycache__/algebra.cpython-312.pyc     |    Bin [31m10980[m -> [32m0[m bytes
 .../lexers/__pycache__/ambient.cpython-312.pyc     |    Bin [31m3112[m -> [32m0[m bytes
 .../lexers/__pycache__/amdgpu.cpython-312.pyc      |    Bin [31m2235[m -> [32m0[m bytes
 .../lexers/__pycache__/ampl.cpython-312.pyc        |    Bin [31m4083[m -> [32m0[m bytes
 .../lexers/__pycache__/apdlexer.cpython-312.pyc    |    Bin [31m19024[m -> [32m0[m bytes
 .../lexers/__pycache__/apl.cpython-312.pyc         |    Bin [31m2504[m -> [32m0[m bytes
 .../lexers/__pycache__/archetype.cpython-312.pyc   |    Bin [31m9176[m -> [32m0[m bytes
 .../lexers/__pycache__/arrow.cpython-312.pyc       |    Bin [31m3554[m -> [32m0[m bytes
 .../lexers/__pycache__/arturo.cpython-312.pyc      |    Bin [31m9731[m -> [32m0[m bytes
 .../lexers/__pycache__/asc.cpython-312.pyc         |    Bin [31m2034[m -> [32m0[m bytes
 .../lexers/__pycache__/asm.cpython-312.pyc         |    Bin [31m35998[m -> [32m0[m bytes
 .../lexers/__pycache__/asn1.cpython-312.pyc        |    Bin [31m4476[m -> [32m0[m bytes
 .../lexers/__pycache__/automation.cpython-312.pyc  |    Bin [31m18402[m -> [32m0[m bytes
 .../lexers/__pycache__/bare.cpython-312.pyc        |    Bin [31m2861[m -> [32m0[m bytes
 .../lexers/__pycache__/basic.cpython-312.pyc       |    Bin [31m26958[m -> [32m0[m bytes
 .../lexers/__pycache__/bdd.cpython-312.pyc         |    Bin [31m2070[m -> [32m0[m bytes
 .../lexers/__pycache__/berry.cpython-312.pyc       |    Bin [31m3544[m -> [32m0[m bytes
 .../lexers/__pycache__/bibtex.cpython-312.pyc      |    Bin [31m5210[m -> [32m0[m bytes
 .../lexers/__pycache__/blueprint.cpython-312.pyc   |    Bin [31m5298[m -> [32m0[m bytes
 .../lexers/__pycache__/boa.cpython-312.pyc         |    Bin [31m3520[m -> [32m0[m bytes
 .../lexers/__pycache__/bqn.cpython-312.pyc         |    Bin [31m2534[m -> [32m0[m bytes
 .../lexers/__pycache__/business.cpython-312.pyc    |    Bin [31m22051[m -> [32m0[m bytes
 .../lexers/__pycache__/c_cpp.cpython-312.pyc       |    Bin [31m16080[m -> [32m0[m bytes
 .../lexers/__pycache__/c_like.cpython-312.pyc      |    Bin [31m27541[m -> [32m0[m bytes
 .../lexers/__pycache__/capnproto.cpython-312.pyc   |    Bin [31m2393[m -> [32m0[m bytes
 .../lexers/__pycache__/carbon.cpython-312.pyc      |    Bin [31m3531[m -> [32m0[m bytes
 .../lexers/__pycache__/cddl.cpython-312.pyc        |    Bin [31m4223[m -> [32m0[m bytes
 .../lexers/__pycache__/chapel.cpython-312.pyc      |    Bin [31m4257[m -> [32m0[m bytes
 .../lexers/__pycache__/clean.cpython-312.pyc       |    Bin [31m6066[m -> [32m0[m bytes
 .../lexers/__pycache__/codeql.cpython-312.pyc      |    Bin [31m2739[m -> [32m0[m bytes
 .../lexers/__pycache__/comal.cpython-312.pyc       |    Bin [31m3213[m -> [32m0[m bytes
 .../lexers/__pycache__/compiled.cpython-312.pyc    |    Bin [31m1986[m -> [32m0[m bytes
 .../lexers/__pycache__/configs.cpython-312.pyc     |    Bin [31m44487[m -> [32m0[m bytes
 .../lexers/__pycache__/console.cpython-312.pyc     |    Bin [31m4236[m -> [32m0[m bytes
 .../lexers/__pycache__/cplint.cpython-312.pyc      |    Bin [31m1748[m -> [32m0[m bytes
 .../lexers/__pycache__/crystal.cpython-312.pyc     |    Bin [31m15136[m -> [32m0[m bytes
 .../lexers/__pycache__/csound.cpython-312.pyc      |    Bin [31m14107[m -> [32m0[m bytes
 .../lexers/__pycache__/css.cpython-312.pyc         |    Bin [31m22083[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/d.cpython-312.pyc  |    Bin [31m8322[m -> [32m0[m bytes
 .../lexers/__pycache__/dalvik.cpython-312.pyc      |    Bin [31m4532[m -> [32m0[m bytes
 .../lexers/__pycache__/data.cpython-312.pyc        |    Bin [31m21149[m -> [32m0[m bytes
 .../lexers/__pycache__/dax.cpython-312.pyc         |    Bin [31m6233[m -> [32m0[m bytes
 .../lexers/__pycache__/devicetree.cpython-312.pyc  |    Bin [31m4033[m -> [32m0[m bytes
 .../lexers/__pycache__/diff.cpython-312.pyc        |    Bin [31m5668[m -> [32m0[m bytes
 .../lexers/__pycache__/dns.cpython-312.pyc         |    Bin [31m3767[m -> [32m0[m bytes
 .../lexers/__pycache__/dotnet.cpython-312.pyc      |    Bin [31m35201[m -> [32m0[m bytes
 .../lexers/__pycache__/dsls.cpython-312.pyc        |    Bin [31m33778[m -> [32m0[m bytes
 .../lexers/__pycache__/dylan.cpython-312.pyc       |    Bin [31m9713[m -> [32m0[m bytes
 .../lexers/__pycache__/ecl.cpython-312.pyc         |    Bin [31m5576[m -> [32m0[m bytes
 .../lexers/__pycache__/eiffel.cpython-312.pyc      |    Bin [31m2983[m -> [32m0[m bytes
 .../lexers/__pycache__/elm.cpython-312.pyc         |    Bin [31m3227[m -> [32m0[m bytes
 .../lexers/__pycache__/elpi.cpython-312.pyc        |    Bin [31m7225[m -> [32m0[m bytes
 .../lexers/__pycache__/email.cpython-312.pyc       |    Bin [31m5973[m -> [32m0[m bytes
 .../lexers/__pycache__/erlang.cpython-312.pyc      |    Bin [31m20514[m -> [32m0[m bytes
 .../lexers/__pycache__/esoteric.cpython-312.pyc    |    Bin [31m9750[m -> [32m0[m bytes
 .../lexers/__pycache__/ezhil.cpython-312.pyc       |    Bin [31m3849[m -> [32m0[m bytes
 .../lexers/__pycache__/factor.cpython-312.pyc      |    Bin [31m16916[m -> [32m0[m bytes
 .../lexers/__pycache__/fantom.cpython-312.pyc      |    Bin [31m7985[m -> [32m0[m bytes
 .../lexers/__pycache__/felix.cpython-312.pyc       |    Bin [31m8240[m -> [32m0[m bytes
 .../lexers/__pycache__/fift.cpython-312.pyc        |    Bin [31m1952[m -> [32m0[m bytes
 .../lexers/__pycache__/floscript.cpython-312.pyc   |    Bin [31m2970[m -> [32m0[m bytes
 .../lexers/__pycache__/forth.cpython-312.pyc       |    Bin [31m5346[m -> [32m0[m bytes
 .../lexers/__pycache__/fortran.cpython-312.pyc     |    Bin [31m8703[m -> [32m0[m bytes
 .../lexers/__pycache__/foxpro.cpython-312.pyc      |    Bin [31m20800[m -> [32m0[m bytes
 .../lexers/__pycache__/freefem.cpython-312.pyc     |    Bin [31m12771[m -> [32m0[m bytes
 .../lexers/__pycache__/func.cpython-312.pyc        |    Bin [31m3326[m -> [32m0[m bytes
 .../lexers/__pycache__/functional.cpython-312.pyc  |    Bin [31m1036[m -> [32m0[m bytes
 .../lexers/__pycache__/futhark.cpython-312.pyc     |    Bin [31m4068[m -> [32m0[m bytes
 .../lexers/__pycache__/gcodelexer.cpython-312.pyc  |    Bin [31m1308[m -> [32m0[m bytes
 .../lexers/__pycache__/gdscript.cpython-312.pyc    |    Bin [31m7202[m -> [32m0[m bytes
 .../lexers/__pycache__/gleam.cpython-312.pyc       |    Bin [31m2700[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/go.cpython-312.pyc |    Bin [31m3375[m -> [32m0[m bytes
 .../__pycache__/grammar_notation.cpython-312.pyc   |    Bin [31m7705[m -> [32m0[m bytes
 .../lexers/__pycache__/graph.cpython-312.pyc       |    Bin [31m3802[m -> [32m0[m bytes
 .../lexers/__pycache__/graphics.cpython-312.pyc    |    Bin [31m29688[m -> [32m0[m bytes
 .../lexers/__pycache__/graphql.cpython-312.pyc     |    Bin [31m4435[m -> [32m0[m bytes
 .../lexers/__pycache__/graphviz.cpython-312.pyc    |    Bin [31m2209[m -> [32m0[m bytes
 .../lexers/__pycache__/gsql.cpython-312.pyc        |    Bin [31m3769[m -> [32m0[m bytes
 .../lexers/__pycache__/hare.cpython-312.pyc        |    Bin [31m2942[m -> [32m0[m bytes
 .../lexers/__pycache__/haskell.cpython-312.pyc     |    Bin [31m30474[m -> [32m0[m bytes
 .../lexers/__pycache__/haxe.cpython-312.pyc        |    Bin [31m22272[m -> [32m0[m bytes
 .../lexers/__pycache__/hdl.cpython-312.pyc         |    Bin [31m17467[m -> [32m0[m bytes
 .../lexers/__pycache__/hexdump.cpython-312.pyc     |    Bin [31m3643[m -> [32m0[m bytes
 .../lexers/__pycache__/html.cpython-312.pyc        |    Bin [31m20717[m -> [32m0[m bytes
 .../lexers/__pycache__/idl.cpython-312.pyc         |    Bin [31m12461[m -> [32m0[m bytes
 .../lexers/__pycache__/igor.cpython-312.pyc        |    Bin [31m25686[m -> [32m0[m bytes
 .../lexers/__pycache__/inferno.cpython-312.pyc     |    Bin [31m3239[m -> [32m0[m bytes
 .../lexers/__pycache__/installers.cpython-312.pyc  |    Bin [31m13763[m -> [32m0[m bytes
 .../lexers/__pycache__/int_fiction.cpython-312.pyc |    Bin [31m48074[m -> [32m0[m bytes
 .../lexers/__pycache__/iolang.cpython-312.pyc      |    Bin [31m2203[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/j.cpython-312.pyc  |    Bin [31m4295[m -> [32m0[m bytes
 .../lexers/__pycache__/javascript.cpython-312.pyc  |    Bin [31m56970[m -> [32m0[m bytes
 .../lexers/__pycache__/jmespath.cpython-312.pyc    |    Bin [31m2393[m -> [32m0[m bytes
 .../lexers/__pycache__/jslt.cpython-312.pyc        |    Bin [31m3751[m -> [32m0[m bytes
 .../lexers/__pycache__/json5.cpython-312.pyc       |    Bin [31m2873[m -> [32m0[m bytes
 .../lexers/__pycache__/jsonnet.cpython-312.pyc     |    Bin [31m4849[m -> [32m0[m bytes
 .../lexers/__pycache__/jsx.cpython-312.pyc         |    Bin [31m2905[m -> [32m0[m bytes
 .../lexers/__pycache__/julia.cpython-312.pyc       |    Bin [31m10928[m -> [32m0[m bytes
 .../lexers/__pycache__/jvm.cpython-312.pyc         |    Bin [31m63860[m -> [32m0[m bytes
 .../lexers/__pycache__/kuin.cpython-312.pyc        |    Bin [31m9873[m -> [32m0[m bytes
 .../lexers/__pycache__/kusto.cpython-312.pyc       |    Bin [31m2835[m -> [32m0[m bytes
 .../lexers/__pycache__/ldap.cpython-312.pyc        |    Bin [31m6419[m -> [32m0[m bytes
 .../lexers/__pycache__/lean.cpython-312.pyc        |    Bin [31m7984[m -> [32m0[m bytes
 .../lexers/__pycache__/lilypond.cpython-312.pyc    |    Bin [31m8364[m -> [32m0[m bytes
 .../lexers/__pycache__/lisp.cpython-312.pyc        |    Bin [31m121579[m -> [32m0[m bytes
 .../lexers/__pycache__/macaulay2.cpython-312.pyc   |    Bin [31m23148[m -> [32m0[m bytes
 .../lexers/__pycache__/make.cpython-312.pyc        |    Bin [31m6657[m -> [32m0[m bytes
 .../lexers/__pycache__/maple.cpython-312.pyc       |    Bin [31m4971[m -> [32m0[m bytes
 .../lexers/__pycache__/markup.cpython-312.pyc      |    Bin [31m60399[m -> [32m0[m bytes
 .../lexers/__pycache__/math.cpython-312.pyc        |    Bin [31m1032[m -> [32m0[m bytes
 .../lexers/__pycache__/matlab.cpython-312.pyc      |    Bin [31m55726[m -> [32m0[m bytes
 .../lexers/__pycache__/maxima.cpython-312.pyc      |    Bin [31m3180[m -> [32m0[m bytes
 .../lexers/__pycache__/meson.cpython-312.pyc       |    Bin [31m3513[m -> [32m0[m bytes
 .../lexers/__pycache__/mime.cpython-312.pyc        |    Bin [31m10109[m -> [32m0[m bytes
 .../lexers/__pycache__/minecraft.cpython-312.pyc   |    Bin [31m10688[m -> [32m0[m bytes
 .../lexers/__pycache__/mips.cpython-312.pyc        |    Bin [31m3427[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/ml.cpython-312.pyc |    Bin [31m26159[m -> [32m0[m bytes
 .../lexers/__pycache__/modeling.cpython-312.pyc    |    Bin [31m12071[m -> [32m0[m bytes
 .../lexers/__pycache__/modula2.cpython-312.pyc     |    Bin [31m26410[m -> [32m0[m bytes
 .../lexers/__pycache__/mojo.cpython-312.pyc        |    Bin [31m14354[m -> [32m0[m bytes
 .../lexers/__pycache__/monte.cpython-312.pyc       |    Bin [31m5105[m -> [32m0[m bytes
 .../lexers/__pycache__/mosel.cpython-312.pyc       |    Bin [31m6954[m -> [32m0[m bytes
 .../lexers/__pycache__/ncl.cpython-312.pyc         |    Bin [31m45906[m -> [32m0[m bytes
 .../lexers/__pycache__/nimrod.cpython-312.pyc      |    Bin [31m6442[m -> [32m0[m bytes
 .../lexers/__pycache__/nit.cpython-312.pyc         |    Bin [31m2748[m -> [32m0[m bytes
 .../lexers/__pycache__/nix.cpython-312.pyc         |    Bin [31m5460[m -> [32m0[m bytes
 .../lexers/__pycache__/numbair.cpython-312.pyc     |    Bin [31m2123[m -> [32m0[m bytes
 .../lexers/__pycache__/oberon.cpython-312.pyc      |    Bin [31m3737[m -> [32m0[m bytes
 .../lexers/__pycache__/objective.cpython-312.pyc   |    Bin [31m19456[m -> [32m0[m bytes
 .../lexers/__pycache__/ooc.cpython-312.pyc         |    Bin [31m3108[m -> [32m0[m bytes
 .../lexers/__pycache__/openscad.cpython-312.pyc    |    Bin [31m3720[m -> [32m0[m bytes
 .../lexers/__pycache__/other.cpython-312.pyc       |    Bin [31m2442[m -> [32m0[m bytes
 .../lexers/__pycache__/parasail.cpython-312.pyc    |    Bin [31m2877[m -> [32m0[m bytes
 .../lexers/__pycache__/parsers.cpython-312.pyc     |    Bin [31m24392[m -> [32m0[m bytes
 .../lexers/__pycache__/pascal.cpython-312.pyc      |    Bin [31m23928[m -> [32m0[m bytes
 .../lexers/__pycache__/pawn.cpython-312.pyc        |    Bin [31m7852[m -> [32m0[m bytes
 .../lexers/__pycache__/pddl.cpython-312.pyc        |    Bin [31m2803[m -> [32m0[m bytes
 .../lexers/__pycache__/perl.cpython-312.pyc        |    Bin [31m39000[m -> [32m0[m bytes
 .../lexers/__pycache__/phix.cpython-312.pyc        |    Bin [31m18414[m -> [32m0[m bytes
 .../lexers/__pycache__/php.cpython-312.pyc         |    Bin [31m14301[m -> [32m0[m bytes
 .../lexers/__pycache__/pointless.cpython-312.pyc   |    Bin [31m2287[m -> [32m0[m bytes
 .../lexers/__pycache__/pony.cpython-312.pyc        |    Bin [31m3416[m -> [32m0[m bytes
 .../lexers/__pycache__/praat.cpython-312.pyc       |    Bin [31m10278[m -> [32m0[m bytes
 .../lexers/__pycache__/procfile.cpython-312.pyc    |    Bin [31m1621[m -> [32m0[m bytes
 .../lexers/__pycache__/prolog.cpython-312.pyc      |    Bin [31m10523[m -> [32m0[m bytes
 .../lexers/__pycache__/promql.cpython-312.pyc      |    Bin [31m3326[m -> [32m0[m bytes
 .../lexers/__pycache__/prql.cpython-312.pyc        |    Bin [31m8374[m -> [32m0[m bytes
 .../lexers/__pycache__/ptx.cpython-312.pyc         |    Bin [31m3762[m -> [32m0[m bytes
 .../lexers/__pycache__/python.cpython-312.pyc      |    Bin [31m42903[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/q.cpython-312.pyc  |    Bin [31m5836[m -> [32m0[m bytes
 .../lexers/__pycache__/qlik.cpython-312.pyc        |    Bin [31m3502[m -> [32m0[m bytes
 .../lexers/__pycache__/qvt.cpython-312.pyc         |    Bin [31m5370[m -> [32m0[m bytes
 .../pygments/lexers/__pycache__/r.cpython-312.pyc  |    Bin [31m6075[m -> [32m0[m bytes
 .../lexers/__pycache__/rdf.cpython-312.pyc         |    Bin [31m12245[m -> [32m0[m bytes
 .../lexers/__pycache__/rebol.cpython-312.pyc       |    Bin [31m19241[m -> [32m0[m bytes
 .../lexers/__pycache__/rego.cpython-312.pyc        |    Bin [31m1866[m -> [32m0[m bytes
 .../lexers/__pycache__/resource.cpython-312.pyc    |    Bin [31m3578[m -> [32m0[m bytes
 .../lexers/__pycache__/ride.cpython-312.pyc        |    Bin [31m4480[m -> [32m0[m bytes
 .../lexers/__pycache__/rita.cpython-312.pyc        |    Bin [31m1461[m -> [32m0[m bytes
 .../lexers/__pycache__/rnc.cpython-312.pyc         |    Bin [31m2003[m -> [32m0[m bytes
 .../lexers/__pycache__/roboconf.cpython-312.pyc    |    Bin [31m2354[m -> [32m0[m bytes
 .../__pycache__/robotframework.cpython-312.pyc     |    Bin [31m29563[m -> [32m0[m bytes
 .../lexers/__pycache__/ruby.cpython-312.pyc        |    Bin [31m22533[m -> [32m0[m bytes
 .../lexers/__pycache__/rust.cpython-312.pyc        |    Bin [31m7296[m -> [32m0[m bytes
 .../lexers/__pycache__/sas.cpython-312.pyc         |    Bin [31m7031[m -> [32m0[m bytes
 .../lexers/__pycache__/savi.cpython-312.pyc        |    Bin [31m3972[m -> [32m0[m bytes
 .../lexers/__pycache__/scdoc.cpython-312.pyc       |    Bin [31m2810[m -> [32m0[m bytes
 .../lexers/__pycache__/scripting.cpython-312.pyc   |    Bin [31m71811[m -> [32m0[m bytes
 .../lexers/__pycache__/sgf.cpython-312.pyc         |    Bin [31m2071[m -> [32m0[m bytes
 .../lexers/__pycache__/shell.cpython-312.pyc       |    Bin [31m37075[m -> [32m0[m bytes
 .../lexers/__pycache__/sieve.cpython-312.pyc       |    Bin [31m2741[m -> [32m0[m bytes
 .../lexers/__pycache__/slash.cpython-312.pyc       |    Bin [31m8384[m -> [32m0[m bytes
 .../lexers/__pycache__/smalltalk.cpython-312.pyc   |    Bin [31m6693[m -> [32m0[m bytes
 .../lexers/__pycache__/smithy.cpython-312.pyc      |    Bin [31m3118[m -> [32m0[m bytes
 .../lexers/__pycache__/smv.cpython-312.pyc         |    Bin [31m2800[m -> [32m0[m bytes
 .../lexers/__pycache__/snobol.cpython-312.pyc      |    Bin [31m2496[m -> [32m0[m bytes
 .../lexers/__pycache__/solidity.cpython-312.pyc    |    Bin [31m3399[m -> [32m0[m bytes
 .../lexers/__pycache__/soong.cpython-312.pyc       |    Bin [31m2264[m -> [32m0[m bytes
 .../lexers/__pycache__/sophia.cpython-312.pyc      |    Bin [31m3844[m -> [32m0[m bytes
 .../lexers/__pycache__/special.cpython-312.pyc     |    Bin [31m5406[m -> [32m0[m bytes
 .../lexers/__pycache__/spice.cpython-312.pyc       |    Bin [31m3169[m -> [32m0[m bytes
 .../lexers/__pycache__/sql.cpython-312.pyc         |    Bin [31m40672[m -> [32m0[m bytes
 .../lexers/__pycache__/srcinfo.cpython-312.pyc     |    Bin [31m1999[m -> [32m0[m bytes
 .../lexers/__pycache__/stata.cpython-312.pyc       |    Bin [31m5151[m -> [32m0[m bytes
 .../__pycache__/supercollider.cpython-312.pyc      |    Bin [31m3901[m -> [32m0[m bytes
 .../lexers/__pycache__/tablegen.cpython-312.pyc    |    Bin [31m3343[m -> [32m0[m bytes
 .../lexers/__pycache__/tact.cpython-312.pyc        |    Bin [31m9028[m -> [32m0[m bytes
 .../lexers/__pycache__/tal.cpython-312.pyc         |    Bin [31m2965[m -> [32m0[m bytes
 .../lexers/__pycache__/tcl.cpython-312.pyc         |    Bin [31m5139[m -> [32m0[m bytes
 .../lexers/__pycache__/teal.cpython-312.pyc        |    Bin [31m3548[m -> [32m0[m bytes
 .../lexers/__pycache__/templates.cpython-312.pyc   |    Bin [31m83629[m -> [32m0[m bytes
 .../lexers/__pycache__/teraterm.cpython-312.pyc    |    Bin [31m5556[m -> [32m0[m bytes
 .../lexers/__pycache__/testing.cpython-312.pyc     |    Bin [31m10064[m -> [32m0[m bytes
 .../lexers/__pycache__/text.cpython-312.pyc        |    Bin [31m1546[m -> [32m0[m bytes
 .../lexers/__pycache__/textedit.cpython-312.pyc    |    Bin [31m8505[m -> [32m0[m bytes
 .../lexers/__pycache__/textfmts.cpython-312.pyc    |    Bin [31m15586[m -> [32m0[m bytes
 .../lexers/__pycache__/theorem.cpython-312.pyc     |    Bin [31m14899[m -> [32m0[m bytes
 .../lexers/__pycache__/thingsdb.cpython-312.pyc    |    Bin [31m5610[m -> [32m0[m bytes
 .../lexers/__pycache__/tlb.cpython-312.pyc         |    Bin [31m1863[m -> [32m0[m bytes
 .../lexers/__pycache__/tls.cpython-312.pyc         |    Bin [31m1921[m -> [32m0[m bytes
 .../lexers/__pycache__/tnt.cpython-312.pyc         |    Bin [31m13577[m -> [32m0[m bytes
 .../__pycache__/trafficscript.cpython-312.pyc      |    Bin [31m1840[m -> [32m0[m bytes
 .../lexers/__pycache__/typoscript.cpython-312.pyc  |    Bin [31m7356[m -> [32m0[m bytes
 .../lexers/__pycache__/typst.cpython-312.pyc       |    Bin [31m6901[m -> [32m0[m bytes
 .../lexers/__pycache__/ul4.cpython-312.pyc         |    Bin [31m8137[m -> [32m0[m bytes
 .../lexers/__pycache__/unicon.cpython-312.pyc      |    Bin [31m12504[m -> [32m0[m bytes
 .../lexers/__pycache__/urbi.cpython-312.pyc        |    Bin [31m5906[m -> [32m0[m bytes
 .../lexers/__pycache__/usd.cpython-312.pyc         |    Bin [31m4019[m -> [32m0[m bytes
 .../lexers/__pycache__/varnish.cpython-312.pyc     |    Bin [31m6941[m -> [32m0[m bytes
 .../__pycache__/verification.cpython-312.pyc       |    Bin [31m4025[m -> [32m0[m bytes
 .../lexers/__pycache__/verifpal.cpython-312.pyc    |    Bin [31m2967[m -> [32m0[m bytes
 .../lexers/__pycache__/vip.cpython-312.pyc         |    Bin [31m5690[m -> [32m0[m bytes
 .../lexers/__pycache__/vyper.cpython-312.pyc       |    Bin [31m4920[m -> [32m0[m bytes
 .../lexers/__pycache__/web.cpython-312.pyc         |    Bin [31m1310[m -> [32m0[m bytes
 .../lexers/__pycache__/webassembly.cpython-312.pyc |    Bin [31m5816[m -> [32m0[m bytes
 .../lexers/__pycache__/webidl.cpython-312.pyc      |    Bin [31m8100[m -> [32m0[m bytes
 .../lexers/__pycache__/webmisc.cpython-312.pyc     |    Bin [31m43537[m -> [32m0[m bytes
 .../lexers/__pycache__/wgsl.cpython-312.pyc        |    Bin [31m10846[m -> [32m0[m bytes
 .../lexers/__pycache__/whiley.cpython-312.pyc      |    Bin [31m3631[m -> [32m0[m bytes
 .../lexers/__pycache__/wowtoc.cpython-312.pyc      |    Bin [31m3236[m -> [32m0[m bytes
 .../lexers/__pycache__/wren.cpython-312.pyc        |    Bin [31m3101[m -> [32m0[m bytes
 .../lexers/__pycache__/x10.cpython-312.pyc         |    Bin [31m2392[m -> [32m0[m bytes
 .../lexers/__pycache__/xorg.cpython-312.pyc        |    Bin [31m1381[m -> [32m0[m bytes
 .../lexers/__pycache__/yang.cpython-312.pyc        |    Bin [31m4145[m -> [32m0[m bytes
 .../lexers/__pycache__/yara.cpython-312.pyc        |    Bin [31m2727[m -> [32m0[m bytes
 .../lexers/__pycache__/zig.cpython-312.pyc         |    Bin [31m3890[m -> [32m0[m bytes
 .../site-packages/pygments/lexers/_ada_builtins.py |    103 [31m-[m
 .../site-packages/pygments/lexers/_asy_builtins.py |   1644 [31m-[m
 .../site-packages/pygments/lexers/_cl_builtins.py  |    231 [31m-[m
 .../pygments/lexers/_cocoa_builtins.py             |     75 [31m-[m
 .../pygments/lexers/_csound_builtins.py            |   1780 [31m-[m
 .../site-packages/pygments/lexers/_css_builtins.py |    558 [31m-[m
 .../pygments/lexers/_googlesql_builtins.py         |    918 [31m-[m
 .../pygments/lexers/_julia_builtins.py             |    411 [31m-[m
 .../pygments/lexers/_lasso_builtins.py             |   5326 [31m-[m
 .../pygments/lexers/_lilypond_builtins.py          |   4932 [31m-[m
 .../site-packages/pygments/lexers/_lua_builtins.py |    285 [31m-[m
 .../pygments/lexers/_luau_builtins.py              |     62 [31m-[m
 .../Lib/site-packages/pygments/lexers/_mapping.py  |    602 [31m-[m
 .../site-packages/pygments/lexers/_mql_builtins.py |   1171 [31m-[m
 .../pygments/lexers/_mysql_builtins.py             |   1335 [31m-[m
 .../pygments/lexers/_openedge_builtins.py          |   2600 [31m-[m
 .../site-packages/pygments/lexers/_php_builtins.py |   3325 [31m-[m
 .../pygments/lexers/_postgres_builtins.py          |    739 [31m-[m
 .../pygments/lexers/_qlik_builtins.py              |    666 [31m-[m
 .../pygments/lexers/_scheme_builtins.py            |   1609 [31m-[m
 .../pygments/lexers/_scilab_builtins.py            |   3093 [31m-[m
 .../pygments/lexers/_sourcemod_builtins.py         |   1151 [31m-[m
 .../site-packages/pygments/lexers/_sql_builtins.py |    106 [31m-[m
 .../pygments/lexers/_stan_builtins.py              |    648 [31m-[m
 .../pygments/lexers/_stata_builtins.py             |    457 [31m-[m
 .../pygments/lexers/_tsql_builtins.py              |   1003 [31m-[m
 .../site-packages/pygments/lexers/_usd_builtins.py |    112 [31m-[m
 .../pygments/lexers/_vbscript_builtins.py          |    279 [31m-[m
 .../site-packages/pygments/lexers/_vim_builtins.py |   1938 [31m-[m
 .../site-packages/pygments/lexers/actionscript.py  |    243 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ada.py  |    144 [31m-[m
 .../Lib/site-packages/pygments/lexers/agile.py     |     25 [31m-[m
 .../Lib/site-packages/pygments/lexers/algebra.py   |    299 [31m-[m
 .../Lib/site-packages/pygments/lexers/ambient.py   |     75 [31m-[m
 .../Lib/site-packages/pygments/lexers/amdgpu.py    |     54 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ampl.py |     87 [31m-[m
 .../Lib/site-packages/pygments/lexers/apdlexer.py  |    593 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/apl.py  |    103 [31m-[m
 .../Lib/site-packages/pygments/lexers/archetype.py |    315 [31m-[m
 .../Lib/site-packages/pygments/lexers/arrow.py     |    116 [31m-[m
 .../Lib/site-packages/pygments/lexers/arturo.py    |    249 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/asc.py  |     55 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/asm.py  |   1051 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/asn1.py |    178 [31m-[m
 .../site-packages/pygments/lexers/automation.py    |    379 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/bare.py |    101 [31m-[m
 .../Lib/site-packages/pygments/lexers/basic.py     |    656 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/bdd.py  |     57 [31m-[m
 .../Lib/site-packages/pygments/lexers/berry.py     |     99 [31m-[m
 .../Lib/site-packages/pygments/lexers/bibtex.py    |    159 [31m-[m
 .../Lib/site-packages/pygments/lexers/blueprint.py |    173 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/boa.py  |     97 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/bqn.py  |    112 [31m-[m
 .../Lib/site-packages/pygments/lexers/business.py  |    625 [31m-[m
 .../Lib/site-packages/pygments/lexers/c_cpp.py     |    414 [31m-[m
 .../Lib/site-packages/pygments/lexers/c_like.py    |    738 [31m-[m
 .../Lib/site-packages/pygments/lexers/capnproto.py |     74 [31m-[m
 .../Lib/site-packages/pygments/lexers/carbon.py    |     95 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/cddl.py |    172 [31m-[m
 .../Lib/site-packages/pygments/lexers/chapel.py    |    139 [31m-[m
 .../Lib/site-packages/pygments/lexers/clean.py     |    180 [31m-[m
 .../Lib/site-packages/pygments/lexers/codeql.py    |     80 [31m-[m
 .../Lib/site-packages/pygments/lexers/comal.py     |     81 [31m-[m
 .../Lib/site-packages/pygments/lexers/compiled.py  |     35 [31m-[m
 .../Lib/site-packages/pygments/lexers/configs.py   |   1433 [31m-[m
 .../Lib/site-packages/pygments/lexers/console.py   |    114 [31m-[m
 .../Lib/site-packages/pygments/lexers/cplint.py    |     43 [31m-[m
 .../Lib/site-packages/pygments/lexers/crystal.py   |    364 [31m-[m
 .../Lib/site-packages/pygments/lexers/csound.py    |    466 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/css.py  |    602 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/d.py    |    259 [31m-[m
 .../Lib/site-packages/pygments/lexers/dalvik.py    |    126 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/data.py |    763 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/dax.py  |    135 [31m-[m
 .../site-packages/pygments/lexers/devicetree.py    |    108 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/diff.py |    169 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/dns.py  |    109 [31m-[m
 .../Lib/site-packages/pygments/lexers/dotnet.py    |    873 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/dsls.py |    970 [31m-[m
 .../Lib/site-packages/pygments/lexers/dylan.py     |    279 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ecl.py  |    144 [31m-[m
 .../Lib/site-packages/pygments/lexers/eiffel.py    |     68 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/elm.py  |    123 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/elpi.py |    175 [31m-[m
 .../Lib/site-packages/pygments/lexers/email.py     |    132 [31m-[m
 .../Lib/site-packages/pygments/lexers/erlang.py    |    526 [31m-[m
 .../Lib/site-packages/pygments/lexers/esoteric.py  |    300 [31m-[m
 .../Lib/site-packages/pygments/lexers/ezhil.py     |     76 [31m-[m
 .../Lib/site-packages/pygments/lexers/factor.py    |    363 [31m-[m
 .../Lib/site-packages/pygments/lexers/fantom.py    |    251 [31m-[m
 .../Lib/site-packages/pygments/lexers/felix.py     |    275 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/fift.py |     68 [31m-[m
 .../Lib/site-packages/pygments/lexers/floscript.py |     81 [31m-[m
 .../Lib/site-packages/pygments/lexers/forth.py     |    178 [31m-[m
 .../Lib/site-packages/pygments/lexers/fortran.py   |    212 [31m-[m
 .../Lib/site-packages/pygments/lexers/foxpro.py    |    427 [31m-[m
 .../Lib/site-packages/pygments/lexers/freefem.py   |    893 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/func.py |    110 [31m-[m
 .../site-packages/pygments/lexers/functional.py    |     21 [31m-[m
 .../Lib/site-packages/pygments/lexers/futhark.py   |    105 [31m-[m
 .../site-packages/pygments/lexers/gcodelexer.py    |     35 [31m-[m
 .../Lib/site-packages/pygments/lexers/gdscript.py  |    189 [31m-[m
 .../Lib/site-packages/pygments/lexers/gleam.py     |     74 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/go.py   |     97 [31m-[m
 .../pygments/lexers/grammar_notation.py            |    262 [31m-[m
 .../Lib/site-packages/pygments/lexers/graph.py     |    108 [31m-[m
 .../Lib/site-packages/pygments/lexers/graphics.py  |    794 [31m-[m
 .../Lib/site-packages/pygments/lexers/graphql.py   |    176 [31m-[m
 .../Lib/site-packages/pygments/lexers/graphviz.py  |     58 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/gsql.py |    103 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/hare.py |     73 [31m-[m
 .../Lib/site-packages/pygments/lexers/haskell.py   |    866 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/haxe.py |    935 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/hdl.py  |    466 [31m-[m
 .../Lib/site-packages/pygments/lexers/hexdump.py   |    102 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/html.py |    670 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/idl.py  |    284 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/igor.py |    435 [31m-[m
 .../Lib/site-packages/pygments/lexers/inferno.py   |     95 [31m-[m
 .../site-packages/pygments/lexers/installers.py    |    352 [31m-[m
 .../site-packages/pygments/lexers/int_fiction.py   |   1370 [31m-[m
 .../Lib/site-packages/pygments/lexers/iolang.py    |     61 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/j.py    |    151 [31m-[m
 .../site-packages/pygments/lexers/javascript.py    |   1591 [31m-[m
 .../Lib/site-packages/pygments/lexers/jmespath.py  |     69 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/jslt.py |     94 [31m-[m
 .../Lib/site-packages/pygments/lexers/json5.py     |     83 [31m-[m
 .../Lib/site-packages/pygments/lexers/jsonnet.py   |    169 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/jsx.py  |    100 [31m-[m
 .../Lib/site-packages/pygments/lexers/julia.py     |    294 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/jvm.py  |   1802 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/kuin.py |    332 [31m-[m
 .../Lib/site-packages/pygments/lexers/kusto.py     |     93 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ldap.py |    155 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/lean.py |    241 [31m-[m
 .../Lib/site-packages/pygments/lexers/lilypond.py  |    225 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/lisp.py |   3146 [31m-[m
 .../Lib/site-packages/pygments/lexers/macaulay2.py |   1814 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/make.py |    212 [31m-[m
 .../Lib/site-packages/pygments/lexers/maple.py     |    291 [31m-[m
 .../Lib/site-packages/pygments/lexers/markup.py    |   1654 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/math.py |     21 [31m-[m
 .../Lib/site-packages/pygments/lexers/matlab.py    |   3307 [31m-[m
 .../Lib/site-packages/pygments/lexers/maxima.py    |     84 [31m-[m
 .../Lib/site-packages/pygments/lexers/meson.py     |    139 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/mime.py |    210 [31m-[m
 .../Lib/site-packages/pygments/lexers/minecraft.py |    391 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/mips.py |    130 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ml.py   |    958 [31m-[m
 .../Lib/site-packages/pygments/lexers/modeling.py  |    366 [31m-[m
 .../Lib/site-packages/pygments/lexers/modula2.py   |   1579 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/mojo.py |    707 [31m-[m
 .../Lib/site-packages/pygments/lexers/monte.py     |    203 [31m-[m
 .../Lib/site-packages/pygments/lexers/mosel.py     |    447 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ncl.py  |    894 [31m-[m
 .../Lib/site-packages/pygments/lexers/nimrod.py    |    199 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/nit.py  |     63 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/nix.py  |    144 [31m-[m
 .../Lib/site-packages/pygments/lexers/numbair.py   |     63 [31m-[m
 .../Lib/site-packages/pygments/lexers/oberon.py    |    120 [31m-[m
 .../Lib/site-packages/pygments/lexers/objective.py |    513 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ooc.py  |     84 [31m-[m
 .../Lib/site-packages/pygments/lexers/openscad.py  |     96 [31m-[m
 .../Lib/site-packages/pygments/lexers/other.py     |     41 [31m-[m
 .../Lib/site-packages/pygments/lexers/parasail.py  |     78 [31m-[m
 .../Lib/site-packages/pygments/lexers/parsers.py   |    798 [31m-[m
 .../Lib/site-packages/pygments/lexers/pascal.py    |    644 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/pawn.py |    202 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/pddl.py |     82 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/perl.py |    733 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/phix.py |    363 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/php.py  |    334 [31m-[m
 .../Lib/site-packages/pygments/lexers/pointless.py |     70 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/pony.py |     93 [31m-[m
 .../Lib/site-packages/pygments/lexers/praat.py     |    303 [31m-[m
 .../Lib/site-packages/pygments/lexers/procfile.py  |     41 [31m-[m
 .../Lib/site-packages/pygments/lexers/prolog.py    |    318 [31m-[m
 .../Lib/site-packages/pygments/lexers/promql.py    |    176 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/prql.py |    251 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ptx.py  |    119 [31m-[m
 .../Lib/site-packages/pygments/lexers/python.py    |   1201 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/q.py    |    187 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/qlik.py |    117 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/qvt.py  |    153 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/r.py    |    196 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/rdf.py  |    468 [31m-[m
 .../Lib/site-packages/pygments/lexers/rebol.py     |    419 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/rego.py |     57 [31m-[m
 .../Lib/site-packages/pygments/lexers/resource.py  |     83 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ride.py |    138 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/rita.py |     42 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/rnc.py  |     66 [31m-[m
 .../Lib/site-packages/pygments/lexers/roboconf.py  |     81 [31m-[m
 .../pygments/lexers/robotframework.py              |    551 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ruby.py |    518 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/rust.py |    222 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/sas.py  |    227 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/savi.py |    171 [31m-[m
 .../Lib/site-packages/pygments/lexers/scdoc.py     |     85 [31m-[m
 .../Lib/site-packages/pygments/lexers/scripting.py |   1616 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/sgf.py  |     59 [31m-[m
 .../Lib/site-packages/pygments/lexers/shell.py     |    902 [31m-[m
 .../Lib/site-packages/pygments/lexers/sieve.py     |     78 [31m-[m
 .../Lib/site-packages/pygments/lexers/slash.py     |    183 [31m-[m
 .../Lib/site-packages/pygments/lexers/smalltalk.py |    194 [31m-[m
 .../Lib/site-packages/pygments/lexers/smithy.py    |     77 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/smv.py  |     78 [31m-[m
 .../Lib/site-packages/pygments/lexers/snobol.py    |     82 [31m-[m
 .../Lib/site-packages/pygments/lexers/solidity.py  |     87 [31m-[m
 .../Lib/site-packages/pygments/lexers/soong.py     |     78 [31m-[m
 .../Lib/site-packages/pygments/lexers/sophia.py    |    102 [31m-[m
 .../Lib/site-packages/pygments/lexers/special.py   |    122 [31m-[m
 .../Lib/site-packages/pygments/lexers/spice.py     |     70 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/sql.py  |   1109 [31m-[m
 .../Lib/site-packages/pygments/lexers/srcinfo.py   |     62 [31m-[m
 .../Lib/site-packages/pygments/lexers/stata.py     |    170 [31m-[m
 .../site-packages/pygments/lexers/supercollider.py |     94 [31m-[m
 .../Lib/site-packages/pygments/lexers/tablegen.py  |    177 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tact.py |    303 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tal.py  |     77 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tcl.py  |    148 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/teal.py |     88 [31m-[m
 .../Lib/site-packages/pygments/lexers/templates.py |   2355 [31m-[m
 .../Lib/site-packages/pygments/lexers/teraterm.py  |    325 [31m-[m
 .../Lib/site-packages/pygments/lexers/testing.py   |    209 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/text.py |     27 [31m-[m
 .../Lib/site-packages/pygments/lexers/textedit.py  |    205 [31m-[m
 .../Lib/site-packages/pygments/lexers/textfmts.py  |    436 [31m-[m
 .../Lib/site-packages/pygments/lexers/theorem.py   |    410 [31m-[m
 .../Lib/site-packages/pygments/lexers/thingsdb.py  |    140 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tlb.py  |     59 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tls.py  |     54 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/tnt.py  |    270 [31m-[m
 .../site-packages/pygments/lexers/trafficscript.py |     51 [31m-[m
 .../site-packages/pygments/lexers/typoscript.py    |    216 [31m-[m
 .../Lib/site-packages/pygments/lexers/typst.py     |    160 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/ul4.py  |    309 [31m-[m
 .../Lib/site-packages/pygments/lexers/unicon.py    |    413 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/urbi.py |    145 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/usd.py  |     85 [31m-[m
 .../Lib/site-packages/pygments/lexers/varnish.py   |    189 [31m-[m
 .../site-packages/pygments/lexers/verification.py  |    113 [31m-[m
 .../Lib/site-packages/pygments/lexers/verifpal.py  |     65 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/vip.py  |    150 [31m-[m
 .../Lib/site-packages/pygments/lexers/vyper.py     |    140 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/web.py  |     24 [31m-[m
 .../site-packages/pygments/lexers/webassembly.py   |    119 [31m-[m
 .../Lib/site-packages/pygments/lexers/webidl.py    |    298 [31m-[m
 .../Lib/site-packages/pygments/lexers/webmisc.py   |   1006 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/wgsl.py |    406 [31m-[m
 .../Lib/site-packages/pygments/lexers/whiley.py    |    115 [31m-[m
 .../Lib/site-packages/pygments/lexers/wowtoc.py    |    120 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/wren.py |     98 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/x10.py  |     66 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/xorg.py |     38 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/yang.py |    103 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/yara.py |     69 [31m-[m
 .../venv/Lib/site-packages/pygments/lexers/zig.py  |    125 [31m-[m
 .../venv/Lib/site-packages/pygments/modeline.py    |     43 [31m-[m
 backend/venv/Lib/site-packages/pygments/plugin.py  |     72 [31m-[m
 .../venv/Lib/site-packages/pygments/regexopt.py    |     91 [31m-[m
 backend/venv/Lib/site-packages/pygments/scanner.py |    104 [31m-[m
 .../venv/Lib/site-packages/pygments/sphinxext.py   |    247 [31m-[m
 backend/venv/Lib/site-packages/pygments/style.py   |    203 [31m-[m
 .../Lib/site-packages/pygments/styles/__init__.py  |     61 [31m-[m
 .../styles/__pycache__/__init__.cpython-312.pyc    |    Bin [31m2607[m -> [32m0[m bytes
 .../styles/__pycache__/_mapping.cpython-312.pyc    |    Bin [31m3627[m -> [32m0[m bytes
 .../styles/__pycache__/abap.cpython-312.pyc        |    Bin [31m1062[m -> [32m0[m bytes
 .../styles/__pycache__/algol.cpython-312.pyc       |    Bin [31m2582[m -> [32m0[m bytes
 .../styles/__pycache__/algol_nu.cpython-312.pyc    |    Bin [31m2597[m -> [32m0[m bytes
 .../styles/__pycache__/arduino.cpython-312.pyc     |    Bin [31m4256[m -> [32m0[m bytes
 .../styles/__pycache__/autumn.cpython-312.pyc      |    Bin [31m2838[m -> [32m0[m bytes
 .../styles/__pycache__/borland.cpython-312.pyc     |    Bin [31m2207[m -> [32m0[m bytes
 .../pygments/styles/__pycache__/bw.cpython-312.pyc |    Bin [31m1884[m -> [32m0[m bytes
 .../styles/__pycache__/coffee.cpython-312.pyc      |    Bin [31m3428[m -> [32m0[m bytes
 .../styles/__pycache__/colorful.cpython-312.pyc    |    Bin [31m3696[m -> [32m0[m bytes
 .../styles/__pycache__/default.cpython-312.pyc     |    Bin [31m3198[m -> [32m0[m bytes
 .../styles/__pycache__/dracula.cpython-312.pyc     |    Bin [31m3011[m -> [32m0[m bytes
 .../styles/__pycache__/emacs.cpython-312.pyc       |    Bin [31m3238[m -> [32m0[m bytes
 .../styles/__pycache__/friendly.cpython-312.pyc    |    Bin [31m3334[m -> [32m0[m bytes
 .../__pycache__/friendly_grayscale.cpython-312.pyc |    Bin [31m3544[m -> [32m0[m bytes
 .../styles/__pycache__/fruity.cpython-312.pyc      |    Bin [31m1913[m -> [32m0[m bytes
 .../styles/__pycache__/gh_dark.cpython-312.pyc     |    Bin [31m4002[m -> [32m0[m bytes
 .../styles/__pycache__/gruvbox.cpython-312.pyc     |    Bin [31m4350[m -> [32m0[m bytes
 .../styles/__pycache__/igor.cpython-312.pyc        |    Bin [31m1107[m -> [32m0[m bytes
 .../styles/__pycache__/inkpot.cpython-312.pyc      |    Bin [31m2969[m -> [32m0[m bytes
 .../styles/__pycache__/lightbulb.cpython-312.pyc   |    Bin [31m4340[m -> [32m0[m bytes
 .../styles/__pycache__/lilypond.cpython-312.pyc    |    Bin [31m3481[m -> [32m0[m bytes
 .../styles/__pycache__/lovelace.cpython-312.pyc    |    Bin [31m4234[m -> [32m0[m bytes
 .../styles/__pycache__/manni.cpython-312.pyc       |    Bin [31m3469[m -> [32m0[m bytes
 .../styles/__pycache__/material.cpython-312.pyc    |    Bin [31m4782[m -> [32m0[m bytes
 .../styles/__pycache__/monokai.cpython-312.pyc     |    Bin [31m4763[m -> [32m0[m bytes
 .../styles/__pycache__/murphy.cpython-312.pyc      |    Bin [31m3654[m -> [32m0[m bytes
 .../styles/__pycache__/native.cpython-312.pyc      |    Bin [31m2931[m -> [32m0[m bytes
 .../styles/__pycache__/nord.cpython-312.pyc        |    Bin [31m5560[m -> [32m0[m bytes
 .../styles/__pycache__/onedark.cpython-312.pyc     |    Bin [31m2237[m -> [32m0[m bytes
 .../__pycache__/paraiso_dark.cpython-312.pyc       |    Bin [31m5103[m -> [32m0[m bytes
 .../__pycache__/paraiso_light.cpython-312.pyc      |    Bin [31m5109[m -> [32m0[m bytes
 .../styles/__pycache__/pastie.cpython-312.pyc      |    Bin [31m3443[m -> [32m0[m bytes
 .../styles/__pycache__/perldoc.cpython-312.pyc     |    Bin [31m3029[m -> [32m0[m bytes
 .../__pycache__/rainbow_dash.cpython-312.pyc       |    Bin [31m3675[m -> [32m0[m bytes
 .../styles/__pycache__/rrt.cpython-312.pyc         |    Bin [31m1437[m -> [32m0[m bytes
 .../styles/__pycache__/sas.cpython-312.pyc         |    Bin [31m1782[m -> [32m0[m bytes
 .../styles/__pycache__/solarized.cpython-312.pyc   |    Bin [31m5734[m -> [32m0[m bytes
 .../styles/__pycache__/staroffice.cpython-312.pyc  |    Bin [31m1085[m -> [32m0[m bytes
 .../styles/__pycache__/stata_dark.cpython-312.pyc  |    Bin [31m1652[m -> [32m0[m bytes
 .../styles/__pycache__/stata_light.cpython-312.pyc |    Bin [31m1653[m -> [32m0[m bytes
 .../styles/__pycache__/tango.cpython-312.pyc       |    Bin [31m6106[m -> [32m0[m bytes
 .../styles/__pycache__/trac.cpython-312.pyc        |    Bin [31m2578[m -> [32m0[m bytes
 .../styles/__pycache__/vim.cpython-312.pyc         |    Bin [31m2461[m -> [32m0[m bytes
 .../pygments/styles/__pycache__/vs.cpython-312.pyc |    Bin [31m1466[m -> [32m0[m bytes
 .../styles/__pycache__/xcode.cpython-312.pyc       |    Bin [31m1804[m -> [32m0[m bytes
 .../styles/__pycache__/zenburn.cpython-312.pyc     |    Bin [31m3313[m -> [32m0[m bytes
 .../Lib/site-packages/pygments/styles/_mapping.py  |     54 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/abap.py |     32 [31m-[m
 .../Lib/site-packages/pygments/styles/algol.py     |     65 [31m-[m
 .../Lib/site-packages/pygments/styles/algol_nu.py  |     65 [31m-[m
 .../Lib/site-packages/pygments/styles/arduino.py   |    100 [31m-[m
 .../Lib/site-packages/pygments/styles/autumn.py    |     67 [31m-[m
 .../Lib/site-packages/pygments/styles/borland.py   |     53 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/bw.py   |     52 [31m-[m
 .../Lib/site-packages/pygments/styles/coffee.py    |     80 [31m-[m
 .../Lib/site-packages/pygments/styles/colorful.py  |     83 [31m-[m
 .../Lib/site-packages/pygments/styles/default.py   |     76 [31m-[m
 .../Lib/site-packages/pygments/styles/dracula.py   |     90 [31m-[m
 .../Lib/site-packages/pygments/styles/emacs.py     |     75 [31m-[m
 .../Lib/site-packages/pygments/styles/friendly.py  |     76 [31m-[m
 .../pygments/styles/friendly_grayscale.py          |     80 [31m-[m
 .../Lib/site-packages/pygments/styles/fruity.py    |     47 [31m-[m
 .../Lib/site-packages/pygments/styles/gh_dark.py   |    113 [31m-[m
 .../Lib/site-packages/pygments/styles/gruvbox.py   |    118 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/igor.py |     32 [31m-[m
 .../Lib/site-packages/pygments/styles/inkpot.py    |     72 [31m-[m
 .../Lib/site-packages/pygments/styles/lightbulb.py |    110 [31m-[m
 .../Lib/site-packages/pygments/styles/lilypond.py  |     62 [31m-[m
 .../Lib/site-packages/pygments/styles/lovelace.py  |    100 [31m-[m
 .../Lib/site-packages/pygments/styles/manni.py     |     79 [31m-[m
 .../Lib/site-packages/pygments/styles/material.py  |    124 [31m-[m
 .../Lib/site-packages/pygments/styles/monokai.py   |    112 [31m-[m
 .../Lib/site-packages/pygments/styles/murphy.py    |     82 [31m-[m
 .../Lib/site-packages/pygments/styles/native.py    |     70 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/nord.py |    156 [31m-[m
 .../Lib/site-packages/pygments/styles/onedark.py   |     63 [31m-[m
 .../site-packages/pygments/styles/paraiso_dark.py  |    124 [31m-[m
 .../site-packages/pygments/styles/paraiso_light.py |    124 [31m-[m
 .../Lib/site-packages/pygments/styles/pastie.py    |     78 [31m-[m
 .../Lib/site-packages/pygments/styles/perldoc.py   |     73 [31m-[m
 .../site-packages/pygments/styles/rainbow_dash.py  |     95 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/rrt.py  |     40 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/sas.py  |     46 [31m-[m
 .../Lib/site-packages/pygments/styles/solarized.py |    144 [31m-[m
 .../site-packages/pygments/styles/staroffice.py    |     31 [31m-[m
 .../site-packages/pygments/styles/stata_dark.py    |     42 [31m-[m
 .../site-packages/pygments/styles/stata_light.py   |     42 [31m-[m
 .../Lib/site-packages/pygments/styles/tango.py     |    143 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/trac.py |     66 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/vim.py  |     67 [31m-[m
 .../venv/Lib/site-packages/pygments/styles/vs.py   |     41 [31m-[m
 .../Lib/site-packages/pygments/styles/xcode.py     |     53 [31m-[m
 .../Lib/site-packages/pygments/styles/zenburn.py   |     83 [31m-[m
 backend/venv/Lib/site-packages/pygments/token.py   |    214 [31m-[m
 .../venv/Lib/site-packages/pygments/unistring.py   |    153 [31m-[m
 backend/venv/Lib/site-packages/pygments/util.py    |    324 [31m-[m
 .../pyparsing-3.3.1.dist-info/INSTALLER            |      1 [31m-[m
 .../pyparsing-3.3.1.dist-info/METADATA             |    143 [31m-[m
 .../site-packages/pyparsing-3.3.1.dist-info/RECORD |     39 [31m-[m
 .../site-packages/pyparsing-3.3.1.dist-info/WHEEL  |      4 [31m-[m
 .../pyparsing-3.3.1.dist-info/licenses/LICENSE     |     20 [31m-[m
 .../venv/Lib/site-packages/pyparsing/__init__.py   |    409 [31m-[m
 .../pyparsing/__pycache__/__init__.cpython-312.pyc |    Bin [31m13472[m -> [32m0[m bytes
 .../pyparsing/__pycache__/actions.cpython-312.pyc  |    Bin [31m9364[m -> [32m0[m bytes
 .../pyparsing/__pycache__/common.cpython-312.pyc   |    Bin [31m16890[m -> [32m0[m bytes
 .../pyparsing/__pycache__/core.cpython-312.pyc     |    Bin [31m286360[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m14738[m -> [32m0[m bytes
 .../pyparsing/__pycache__/helpers.cpython-312.pyc  |    Bin [31m48767[m -> [32m0[m bytes
 .../pyparsing/__pycache__/results.cpython-312.pyc  |    Bin [31m36389[m -> [32m0[m bytes
 .../pyparsing/__pycache__/testing.cpython-312.pyc  |    Bin [31m19295[m -> [32m0[m bytes
 .../pyparsing/__pycache__/unicode.cpython-312.pyc  |    Bin [31m13473[m -> [32m0[m bytes
 .../pyparsing/__pycache__/util.cpython-312.pyc     |    Bin [31m22556[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pyparsing/actions.py    |    264 [31m-[m
 .../Lib/site-packages/pyparsing/ai/__init__.py     |      0
 .../ai/__pycache__/__init__.cpython-312.pyc        |    Bin [31m174[m -> [32m0[m bytes
 .../site-packages/pyparsing/ai/best_practices.md   |     75 [31m-[m
 .../pyparsing/ai/show_best_practices/__init__.py   |      0
 .../pyparsing/ai/show_best_practices/__main__.py   |      2 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m194[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m287[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pyparsing/common.py |    532 [31m-[m
 backend/venv/Lib/site-packages/pyparsing/core.py   |   6953 [31m-[m
 .../site-packages/pyparsing/diagram/__init__.py    |    761 [31m-[m
 .../diagram/__pycache__/__init__.cpython-312.pyc   |    Bin [31m29597[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pyparsing/exceptions.py |    352 [31m-[m
 .../venv/Lib/site-packages/pyparsing/helpers.py    |   1217 [31m-[m
 backend/venv/Lib/site-packages/pyparsing/py.typed  |      0
 .../venv/Lib/site-packages/pyparsing/results.py    |    941 [31m-[m
 .../venv/Lib/site-packages/pyparsing/testing.py    |    398 [31m-[m
 .../Lib/site-packages/pyparsing/tools/__init__.py  |      0
 .../tools/__pycache__/__init__.cpython-312.pyc     |    Bin [31m177[m -> [32m0[m bytes
 .../cvt_pyparsing_pep8_names.cpython-312.pyc       |    Bin [31m8540[m -> [32m0[m bytes
 .../pyparsing/tools/cvt_pyparsing_pep8_names.py    |    142 [31m-[m
 .../venv/Lib/site-packages/pyparsing/unicode.py    |    356 [31m-[m
 backend/venv/Lib/site-packages/pyparsing/util.py   |    486 [31m-[m
 .../site-packages/pytest-9.0.2.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/pytest-9.0.2.dist-info/METADATA  |    212 [31m-[m
 .../site-packages/pytest-9.0.2.dist-info/RECORD    |    160 [31m-[m
 .../site-packages/pytest-9.0.2.dist-info/REQUESTED |      0
 .../Lib/site-packages/pytest-9.0.2.dist-info/WHEEL |      5 [31m-[m
 .../pytest-9.0.2.dist-info/entry_points.txt        |      3 [31m-[m
 .../pytest-9.0.2.dist-info/licenses/LICENSE        |     21 [31m-[m
 .../pytest-9.0.2.dist-info/top_level.txt           |      3 [31m-[m
 backend/venv/Lib/site-packages/pytest/__init__.py  |    186 [31m-[m
 backend/venv/Lib/site-packages/pytest/__main__.py  |      9 [31m-[m
 .../pytest/__pycache__/__init__.cpython-312.pyc    |    Bin [31m4481[m -> [32m0[m bytes
 .../pytest/__pycache__/__main__.cpython-312.pyc    |    Bin [31m417[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytest/py.typed     |      0
 .../pytest_asyncio-1.3.0.dist-info/INSTALLER       |      1 [31m-[m
 .../pytest_asyncio-1.3.0.dist-info/METADATA        |     91 [31m-[m
 .../pytest_asyncio-1.3.0.dist-info/RECORD          |     13 [31m-[m
 .../pytest_asyncio-1.3.0.dist-info/REQUESTED       |      0
 .../pytest_asyncio-1.3.0.dist-info/WHEEL           |      5 [31m-[m
 .../entry_points.txt                               |      2 [31m-[m
 .../licenses/LICENSE                               |    201 [31m-[m
 .../pytest_asyncio-1.3.0.dist-info/top_level.txt   |      1 [31m-[m
 .../Lib/site-packages/pytest_asyncio/__init__.py   |     11 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m479[m -> [32m0[m bytes
 .../__pycache__/plugin.cpython-312.pyc             |    Bin [31m39283[m -> [32m0[m bytes
 .../Lib/site-packages/pytest_asyncio/plugin.py     |    896 [31m-[m
 .../venv/Lib/site-packages/pytest_asyncio/py.typed |      0
 .../INSTALLER                                      |      1 [31m-[m
 .../python_dateutil-2.9.0.post0.dist-info/LICENSE  |     54 [31m-[m
 .../python_dateutil-2.9.0.post0.dist-info/METADATA |    204 [31m-[m
 .../python_dateutil-2.9.0.post0.dist-info/RECORD   |     44 [31m-[m
 .../python_dateutil-2.9.0.post0.dist-info/WHEEL    |      6 [31m-[m
 .../top_level.txt                                  |      1 [31m-[m
 .../python_dateutil-2.9.0.post0.dist-info/zip-safe |      1 [31m-[m
 .../python_dotenv-1.2.1.dist-info/INSTALLER        |      1 [31m-[m
 .../python_dotenv-1.2.1.dist-info/METADATA         |    749 [31m-[m
 .../python_dotenv-1.2.1.dist-info/RECORD           |     26 [31m-[m
 .../python_dotenv-1.2.1.dist-info/REQUESTED        |      0
 .../python_dotenv-1.2.1.dist-info/WHEEL            |      5 [31m-[m
 .../python_dotenv-1.2.1.dist-info/entry_points.txt |      2 [31m-[m
 .../python_dotenv-1.2.1.dist-info/licenses/LICENSE |     27 [31m-[m
 .../python_dotenv-1.2.1.dist-info/top_level.txt    |      1 [31m-[m
 .../python_jose-3.5.0.dist-info/INSTALLER          |      1 [31m-[m
 .../python_jose-3.5.0.dist-info/METADATA           |    149 [31m-[m
 .../python_jose-3.5.0.dist-info/RECORD             |     37 [31m-[m
 .../python_jose-3.5.0.dist-info/REQUESTED          |      0
 .../python_jose-3.5.0.dist-info/WHEEL              |      6 [31m-[m
 .../python_jose-3.5.0.dist-info/licenses/LICENSE   |     22 [31m-[m
 .../python_jose-3.5.0.dist-info/top_level.txt      |      1 [31m-[m
 .../python_multipart-0.0.21.dist-info/INSTALLER    |      1 [31m-[m
 .../python_multipart-0.0.21.dist-info/METADATA     |     40 [31m-[m
 .../python_multipart-0.0.21.dist-info/RECORD       |     23 [31m-[m
 .../python_multipart-0.0.21.dist-info/REQUESTED    |      0
 .../python_multipart-0.0.21.dist-info/WHEEL        |      4 [31m-[m
 .../licenses/LICENSE.txt                           |     14 [31m-[m
 .../Lib/site-packages/python_multipart/__init__.py |     25 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m570[m -> [32m0[m bytes
 .../__pycache__/decoders.cpython-312.pyc           |    Bin [31m8348[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m1739[m -> [32m0[m bytes
 .../__pycache__/multipart.cpython-312.pyc          |    Bin [31m67704[m -> [32m0[m bytes
 .../Lib/site-packages/python_multipart/decoders.py |    185 [31m-[m
 .../site-packages/python_multipart/exceptions.py   |     34 [31m-[m
 .../site-packages/python_multipart/multipart.py    |   1872 [31m-[m
 .../Lib/site-packages/python_multipart/py.typed    |      0
 .../site-packages/pytz-2025.2.dist-info/INSTALLER  |      1 [31m-[m
 .../pytz-2025.2.dist-info/LICENSE.txt              |     19 [31m-[m
 .../site-packages/pytz-2025.2.dist-info/METADATA   |    648 [31m-[m
 .../Lib/site-packages/pytz-2025.2.dist-info/RECORD |    623 [31m-[m
 .../Lib/site-packages/pytz-2025.2.dist-info/WHEEL  |      6 [31m-[m
 .../pytz-2025.2.dist-info/top_level.txt            |      1 [31m-[m
 .../site-packages/pytz-2025.2.dist-info/zip-safe   |      1 [31m-[m
 backend/venv/Lib/site-packages/pytz/__init__.py    |   1556 [31m-[m
 .../pytz/__pycache__/__init__.cpython-312.pyc      |    Bin [31m30502[m -> [32m0[m bytes
 .../pytz/__pycache__/exceptions.cpython-312.pyc    |    Bin [31m2291[m -> [32m0[m bytes
 .../pytz/__pycache__/lazy.cpython-312.pyc          |    Bin [31m7667[m -> [32m0[m bytes
 .../pytz/__pycache__/reference.cpython-312.pyc     |    Bin [31m5524[m -> [32m0[m bytes
 .../pytz/__pycache__/tzfile.cpython-312.pyc        |    Bin [31m5247[m -> [32m0[m bytes
 .../pytz/__pycache__/tzinfo.cpython-312.pyc        |    Bin [31m19255[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/exceptions.py  |     59 [31m-[m
 backend/venv/Lib/site-packages/pytz/lazy.py        |    172 [31m-[m
 backend/venv/Lib/site-packages/pytz/reference.py   |    140 [31m-[m
 backend/venv/Lib/site-packages/pytz/tzfile.py      |    133 [31m-[m
 backend/venv/Lib/site-packages/pytz/tzinfo.py      |    580 [31m-[m
 .../Lib/site-packages/pytz/zoneinfo/Africa/Abidjan |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Accra   |    Bin [31m148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Addis_Ababa |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Algiers |    Bin [31m735[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Asmara  |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Asmera  |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Bamako  |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Bangui  |    Bin [31m235[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Banjul  |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Bissau  |    Bin [31m194[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Blantyre    |    Bin [31m149[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Brazzaville |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Bujumbura   |    Bin [31m149[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Cairo   |    Bin [31m2399[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Casablanca  |    Bin [31m2429[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Ceuta   |    Bin [31m2052[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Conakry |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Dakar   |    Bin [31m148[m -> [32m0[m bytes
 .../pytz/zoneinfo/Africa/Dar_es_Salaam             |    Bin [31m265[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Djibouti    |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Douala  |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/El_Aaiun    |    Bin [31m2295[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Freetown    |    Bin [31m148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Gaborone    |    Bin [31m149[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Harare  |    Bin [31m149[m -> [32m0[m bytes
 .../pytz/zoneinfo/Africa/Johannesburg              |    Bin [31m246[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Juba    |    Bin [31m679[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Kampala |    Bin [31m265[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Khartoum    |    Bin [31m679[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Kigali  |    Bin [31m149[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Kinshasa    |    Bin [31m235[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Lagos   |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Libreville  |    Bin [31m235[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Lome    |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Luanda  |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Lubumbashi  |    Bin [31m149[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Lusaka  |    Bin [31m149[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Malabo  |    Bin [31m235[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Maputo  |    Bin [31m149[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Maseru  |    Bin [31m246[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Mbabane |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Mogadishu   |    Bin [31m265[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Monrovia    |    Bin [31m208[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Nairobi |    Bin [31m265[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Ndjamena    |    Bin [31m199[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Niamey  |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Nouakchott  |    Bin [31m148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Ouagadougou |    Bin [31m148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Porto-Novo  |    Bin [31m235[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Sao_Tome    |    Bin [31m254[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Timbuktu    |    Bin [31m148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Tripoli |    Bin [31m625[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Africa/Tunis   |    Bin [31m689[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Africa/Windhoek    |    Bin [31m955[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Adak   |    Bin [31m2356[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Anchorage  |    Bin [31m2371[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Anguilla   |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Antigua    |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Araguaina  |    Bin [31m870[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Buenos_Aires   |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Catamarca      |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/ComodRivadavia |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Cordoba        |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Jujuy          |    Bin [31m1034[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/La_Rioja       |    Bin [31m1076[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Mendoza        |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Rio_Gallegos   |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Salta          |    Bin [31m1034[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/San_Juan       |    Bin [31m1076[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/San_Luis       |    Bin [31m1088[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Tucuman        |    Bin [31m1090[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Argentina/Ushuaia        |    Bin [31m1062[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Aruba  |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Asuncion   |    Bin [31m1644[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Atikokan   |    Bin [31m182[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Atka   |    Bin [31m2356[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Bahia  |    Bin [31m1010[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Bahia_Banderas           |    Bin [31m1100[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Barbados   |    Bin [31m436[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Belem  |    Bin [31m562[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Belize |    Bin [31m1614[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Blanc-Sablon             |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Boa_Vista  |    Bin [31m618[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Bogota |    Bin [31m232[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Boise  |    Bin [31m2410[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Buenos_Aires             |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Cambridge_Bay            |    Bin [31m2254[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Campo_Grande             |    Bin [31m1430[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Cancun |    Bin [31m864[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Caracas    |    Bin [31m250[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Catamarca  |    Bin [31m1062[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Cayenne    |    Bin [31m184[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Cayman |    Bin [31m182[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Chicago    |    Bin [31m3592[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Chihuahua  |    Bin [31m1102[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Ciudad_Juarez            |    Bin [31m1538[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Coral_Harbour            |    Bin [31m182[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Cordoba    |    Bin [31m1062[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Costa_Rica |    Bin [31m316[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Coyhaique  |    Bin [31m2126[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Creston    |    Bin [31m360[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Cuiaba |    Bin [31m1402[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Curacao    |    Bin [31m246[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Danmarkshavn             |    Bin [31m698[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Dawson |    Bin [31m1614[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Dawson_Creek             |    Bin [31m1050[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Denver |    Bin [31m2460[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Detroit    |    Bin [31m2230[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Dominica   |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Edmonton   |    Bin [31m2332[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Eirunepe   |    Bin [31m642[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/El_Salvador              |    Bin [31m224[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Ensenada   |    Bin [31m2458[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Fort_Nelson              |    Bin [31m2240[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Fort_Wayne |    Bin [31m1682[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Fortaleza  |    Bin [31m702[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Glace_Bay  |    Bin [31m2192[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Godthab    |    Bin [31m1889[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Goose_Bay  |    Bin [31m3210[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Grand_Turk |    Bin [31m1834[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Grenada    |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Guadeloupe |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Guatemala  |    Bin [31m280[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Guayaquil  |    Bin [31m232[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Guyana |    Bin [31m248[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Halifax    |    Bin [31m3424[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Havana |    Bin [31m2416[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Hermosillo |    Bin [31m388[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Indianapolis     |    Bin [31m1682[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Knox             |    Bin [31m2444[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Marengo          |    Bin [31m1738[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Petersburg       |    Bin [31m1920[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Tell_City        |    Bin [31m1700[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Vevay            |    Bin [31m1430[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Vincennes        |    Bin [31m1710[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indiana/Winamac          |    Bin [31m1794[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Indianapolis             |    Bin [31m1682[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Inuvik |    Bin [31m2074[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Iqaluit    |    Bin [31m2202[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Jamaica    |    Bin [31m482[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Jujuy  |    Bin [31m1034[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Juneau |    Bin [31m2353[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Kentucky/Louisville      |    Bin [31m2788[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Kentucky/Monticello      |    Bin [31m2368[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Knox_IN    |    Bin [31m2444[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Kralendijk |    Bin [31m246[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/La_Paz |    Bin [31m218[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Lima   |    Bin [31m392[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Los_Angeles              |    Bin [31m2852[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Louisville |    Bin [31m2788[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Lower_Princes            |    Bin [31m246[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Maceio |    Bin [31m730[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Managua    |    Bin [31m430[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Manaus |    Bin [31m590[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Marigot    |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Martinique |    Bin [31m232[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Matamoros  |    Bin [31m1418[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Mazatlan   |    Bin [31m1060[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Mendoza    |    Bin [31m1062[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Menominee  |    Bin [31m2274[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Merida |    Bin [31m1004[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Metlakatla |    Bin [31m1423[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Mexico_City              |    Bin [31m1222[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Miquelon   |    Bin [31m1652[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Moncton    |    Bin [31m3154[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Monterrey  |    Bin [31m1114[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Montevideo |    Bin [31m1496[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Montreal   |    Bin [31m3494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Montserrat |    Bin [31m246[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Nassau |    Bin [31m3494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/New_York   |    Bin [31m3552[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Nipigon    |    Bin [31m3494[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Nome   |    Bin [31m2367[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Noronha    |    Bin [31m702[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/North_Dakota/Beulah      |    Bin [31m2396[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/North_Dakota/Center      |    Bin [31m2396[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/North_Dakota/New_Salem   |    Bin [31m2396[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Nuuk   |    Bin [31m1889[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Ojinaga    |    Bin [31m1524[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Panama |    Bin [31m182[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Pangnirtung              |    Bin [31m2202[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Paramaribo |    Bin [31m248[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Phoenix    |    Bin [31m360[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Port-au-Prince           |    Bin [31m1434[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Port_of_Spain            |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Porto_Acre |    Bin [31m614[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Porto_Velho              |    Bin [31m562[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Puerto_Rico              |    Bin [31m246[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Punta_Arenas             |    Bin [31m1902[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Rainy_River              |    Bin [31m2868[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Rankin_Inlet             |    Bin [31m2066[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Recife |    Bin [31m702[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Regina |    Bin [31m980[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Resolute   |    Bin [31m2066[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Rio_Branco |    Bin [31m614[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Rosario    |    Bin [31m1062[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Santa_Isabel             |    Bin [31m2458[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Santarem   |    Bin [31m588[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Santiago   |    Bin [31m2515[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Santo_Domingo            |    Bin [31m458[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Sao_Paulo  |    Bin [31m1430[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Scoresbysund             |    Bin [31m1935[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Shiprock   |    Bin [31m2460[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Sitka  |    Bin [31m2329[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/St_Barthelemy            |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/St_Johns   |    Bin [31m3655[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/St_Kitts   |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/St_Lucia   |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/St_Thomas  |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/St_Vincent |    Bin [31m246[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Swift_Current            |    Bin [31m560[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Tegucigalpa              |    Bin [31m252[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Thule  |    Bin [31m1502[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Thunder_Bay              |    Bin [31m3494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Tijuana    |    Bin [31m2458[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Toronto    |    Bin [31m3494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Tortola    |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Vancouver  |    Bin [31m2892[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/America/Virgin |    Bin [31m246[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Whitehorse |    Bin [31m1614[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Winnipeg   |    Bin [31m2868[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/America/Yakutat    |    Bin [31m2305[m -> [32m0[m bytes
 .../pytz/zoneinfo/America/Yellowknife              |    Bin [31m2332[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Casey   |    Bin [31m423[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Davis   |    Bin [31m283[m -> [32m0[m bytes
 .../pytz/zoneinfo/Antarctica/DumontDUrville        |    Bin [31m172[m -> [32m0[m bytes
 .../pytz/zoneinfo/Antarctica/Macquarie             |    Bin [31m2260[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Mawson  |    Bin [31m185[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/McMurdo |    Bin [31m2437[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Palmer  |    Bin [31m1404[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Rothera |    Bin [31m150[m -> [32m0[m bytes
 .../pytz/zoneinfo/Antarctica/South_Pole            |    Bin [31m2437[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Syowa   |    Bin [31m151[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Troll   |    Bin [31m1148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Antarctica/Vostok  |    Bin [31m213[m -> [32m0[m bytes
 .../pytz/zoneinfo/Arctic/Longyearbyen              |    Bin [31m2298[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Aden |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Almaty    |    Bin [31m983[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Amman     |    Bin [31m1433[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Anadyr    |    Bin [31m1174[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Aqtau     |    Bin [31m969[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Aqtobe    |    Bin [31m997[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Ashgabat  |    Bin [31m605[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Ashkhabad |    Bin [31m605[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Atyrau    |    Bin [31m977[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Baghdad   |    Bin [31m969[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Bahrain   |    Bin [31m185[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Baku |    Bin [31m1213[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Bangkok   |    Bin [31m185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Barnaul   |    Bin [31m1207[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Beirut    |    Bin [31m2154[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Bishkek   |    Bin [31m969[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Brunei    |    Bin [31m469[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Calcutta  |    Bin [31m285[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Chita     |    Bin [31m1207[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Choibalsan    |    Bin [31m877[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Chongqing |    Bin [31m561[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Chungking |    Bin [31m561[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Colombo   |    Bin [31m358[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Dacca     |    Bin [31m323[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Damascus  |    Bin [31m1873[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Dhaka     |    Bin [31m323[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Dili |    Bin [31m257[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Dubai     |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Dushanbe  |    Bin [31m577[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Famagusta |    Bin [31m2028[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Gaza |    Bin [31m3844[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Harbin    |    Bin [31m561[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Hebron    |    Bin [31m3872[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Ho_Chi_Minh   |    Bin [31m337[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Hong_Kong |    Bin [31m1233[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Hovd |    Bin [31m877[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Irkutsk   |    Bin [31m1229[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Istanbul  |    Bin [31m1933[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Jakarta   |    Bin [31m383[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Jayapura  |    Bin [31m221[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Jerusalem |    Bin [31m2388[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kabul     |    Bin [31m194[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kamchatka |    Bin [31m1152[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Karachi   |    Bin [31m379[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kashgar   |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kathmandu |    Bin [31m198[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Katmandu  |    Bin [31m198[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Khandyga  |    Bin [31m1257[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kolkata   |    Bin [31m285[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Krasnoyarsk   |    Bin [31m1193[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Kuala_Lumpur  |    Bin [31m401[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kuching   |    Bin [31m469[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Kuwait    |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Macao     |    Bin [31m1227[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Macau     |    Bin [31m1227[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Magadan   |    Bin [31m1208[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Makassar  |    Bin [31m254[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Manila    |    Bin [31m422[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Muscat    |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Nicosia   |    Bin [31m2002[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Novokuznetsk  |    Bin [31m1151[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Novosibirsk   |    Bin [31m1207[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Omsk |    Bin [31m1193[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Asia/Oral |    Bin [31m991[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Phnom_Penh    |    Bin [31m185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Pontianak |    Bin [31m353[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Pyongyang |    Bin [31m237[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Qatar     |    Bin [31m185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Qostanay  |    Bin [31m1025[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Qyzylorda |    Bin [31m1011[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Rangoon   |    Bin [31m254[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Riyadh    |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Saigon    |    Bin [31m337[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Sakhalin  |    Bin [31m1188[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Samarkand |    Bin [31m563[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Seoul     |    Bin [31m617[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Shanghai  |    Bin [31m561[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Singapore |    Bin [31m401[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Srednekolymsk |    Bin [31m1194[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Taipei    |    Bin [31m761[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tashkent  |    Bin [31m577[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tbilisi   |    Bin [31m1021[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tehran    |    Bin [31m1248[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tel_Aviv  |    Bin [31m2388[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Thimbu    |    Bin [31m189[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Thimphu   |    Bin [31m189[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tokyo     |    Bin [31m309[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Tomsk     |    Bin [31m1207[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Ujung_Pandang |    Bin [31m254[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Ulaanbaatar   |    Bin [31m877[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Ulan_Bator    |    Bin [31m877[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Urumqi    |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Ust-Nera  |    Bin [31m1238[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Vientiane |    Bin [31m185[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Vladivostok   |    Bin [31m1194[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Yakutsk   |    Bin [31m1193[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Yangon    |    Bin [31m254[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Asia/Yekaterinburg |    Bin [31m1229[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Asia/Yerevan   |    Bin [31m1137[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Azores    |    Bin [31m3442[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Bermuda   |    Bin [31m2396[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Canary    |    Bin [31m1897[m -> [32m0[m bytes
 .../pytz/zoneinfo/Atlantic/Cape_Verde              |    Bin [31m256[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Faeroe    |    Bin [31m1815[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Atlantic/Faroe |    Bin [31m1815[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Jan_Mayen |    Bin [31m2298[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Madeira   |    Bin [31m3377[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Reykjavik |    Bin [31m148[m -> [32m0[m bytes
 .../pytz/zoneinfo/Atlantic/South_Georgia           |    Bin [31m150[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/St_Helena |    Bin [31m148[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Atlantic/Stanley   |    Bin [31m1200[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Australia/ACT  |    Bin [31m2190[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Adelaide |    Bin [31m2208[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Brisbane |    Bin [31m419[m -> [32m0[m bytes
 .../pytz/zoneinfo/Australia/Broken_Hill            |    Bin [31m2229[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Canberra |    Bin [31m2190[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Currie   |    Bin [31m2358[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Darwin   |    Bin [31m325[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Eucla    |    Bin [31m456[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Hobart   |    Bin [31m2358[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Australia/LHI  |    Bin [31m1846[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Lindeman |    Bin [31m475[m -> [32m0[m bytes
 .../pytz/zoneinfo/Australia/Lord_Howe              |    Bin [31m1846[m -> [32m0[m bytes
 .../pytz/zoneinfo/Australia/Melbourne              |    Bin [31m2190[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Australia/NSW  |    Bin [31m2190[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/North    |    Bin [31m325[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Perth    |    Bin [31m446[m -> [32m0[m bytes
 .../pytz/zoneinfo/Australia/Queensland             |    Bin [31m419[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/South    |    Bin [31m2208[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Sydney   |    Bin [31m2190[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Tasmania |    Bin [31m2358[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Australia/Victoria |    Bin [31m2190[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Australia/West |    Bin [31m446[m -> [32m0[m bytes
 .../pytz/zoneinfo/Australia/Yancowinna             |    Bin [31m2229[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Brazil/Acre    |    Bin [31m614[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Brazil/DeNoronha   |    Bin [31m702[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Brazil/East    |    Bin [31m1430[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Brazil/West    |    Bin [31m590[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/CET   |    Bin [31m2933[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/CST6CDT   |    Bin [31m3592[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Canada/Atlantic    |    Bin [31m3424[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Canada/Central |    Bin [31m2868[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Canada/Eastern |    Bin [31m3494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Canada/Mountain    |    Bin [31m2332[m -> [32m0[m bytes
 .../pytz/zoneinfo/Canada/Newfoundland              |    Bin [31m3655[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Canada/Pacific |    Bin [31m2892[m -> [32m0[m bytes
 .../pytz/zoneinfo/Canada/Saskatchewan              |    Bin [31m980[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Canada/Yukon   |    Bin [31m1614[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Chile/Continental  |    Bin [31m2515[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Chile/EasterIsland |    Bin [31m2219[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Cuba  |    Bin [31m2416[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/EET   |    Bin [31m2262[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/EST   |    Bin [31m182[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/EST5EDT   |    Bin [31m3552[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Egypt |    Bin [31m2399[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Eire  |    Bin [31m3492[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT   |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+0 |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+1 |    Bin [31m116[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT+10     |    Bin [31m117[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT+11     |    Bin [31m117[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT+12     |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+2 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+3 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+4 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+5 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+6 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+7 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+8 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT+9 |    Bin [31m116[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-0 |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-1 |    Bin [31m117[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT-10     |    Bin [31m118[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT-11     |    Bin [31m118[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT-12     |    Bin [31m118[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT-13     |    Bin [31m118[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/GMT-14     |    Bin [31m118[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-2 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-3 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-4 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-5 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-6 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-7 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-8 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT-9 |    Bin [31m117[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/GMT0  |    Bin [31m114[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/Greenwich  |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/UCT   |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/UTC   |    Bin [31m114[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Etc/Universal  |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Etc/Zulu  |    Bin [31m114[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Amsterdam   |    Bin [31m2933[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Andorra |    Bin [31m1742[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Astrakhan   |    Bin [31m1151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Athens  |    Bin [31m2262[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Belfast |    Bin [31m3664[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Belgrade    |    Bin [31m1920[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Berlin  |    Bin [31m2298[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Bratislava  |    Bin [31m2301[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Brussels    |    Bin [31m2933[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Bucharest   |    Bin [31m2184[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Budapest    |    Bin [31m2368[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Busingen    |    Bin [31m1909[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Chisinau    |    Bin [31m2390[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Copenhagen  |    Bin [31m2298[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Dublin  |    Bin [31m3492[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Gibraltar   |    Bin [31m3068[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Guernsey    |    Bin [31m3664[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Helsinki    |    Bin [31m1900[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Isle_of_Man |    Bin [31m3664[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Istanbul    |    Bin [31m1933[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Jersey  |    Bin [31m3664[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Kaliningrad |    Bin [31m1493[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Kiev    |    Bin [31m2120[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Kirov   |    Bin [31m1185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Kyiv    |    Bin [31m2120[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Lisbon  |    Bin [31m3527[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Ljubljana   |    Bin [31m1920[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/London  |    Bin [31m3664[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Luxembourg  |    Bin [31m2933[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Madrid  |    Bin [31m2614[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Malta   |    Bin [31m2620[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Mariehamn   |    Bin [31m1900[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Minsk   |    Bin [31m1307[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Monaco  |    Bin [31m2962[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Moscow  |    Bin [31m1535[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Nicosia |    Bin [31m2002[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Oslo    |    Bin [31m2298[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Paris   |    Bin [31m2962[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Podgorica   |    Bin [31m1920[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Prague  |    Bin [31m2301[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Riga    |    Bin [31m2198[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Rome    |    Bin [31m2641[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Samara  |    Bin [31m1201[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/San_Marino  |    Bin [31m2641[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Sarajevo    |    Bin [31m1920[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Saratov |    Bin [31m1169[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Simferopol  |    Bin [31m1469[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Skopje  |    Bin [31m1920[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Sofia   |    Bin [31m2077[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Stockholm   |    Bin [31m2298[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Tallinn |    Bin [31m2148[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Tirane  |    Bin [31m2084[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Tiraspol    |    Bin [31m2390[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Ulyanovsk   |    Bin [31m1253[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Uzhgorod    |    Bin [31m2120[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Vaduz   |    Bin [31m1909[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Vatican |    Bin [31m2641[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Vienna  |    Bin [31m2200[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Vilnius |    Bin [31m2162[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Volgograd   |    Bin [31m1193[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Warsaw  |    Bin [31m2654[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Zagreb  |    Bin [31m1920[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Europe/Zaporozhye  |    Bin [31m2120[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Europe/Zurich  |    Bin [31m1909[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Factory   |    Bin [31m116[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/GB    |    Bin [31m3664[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/GB-Eire   |    Bin [31m3664[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/GMT   |    Bin [31m114[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/GMT+0 |    Bin [31m114[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/GMT-0 |    Bin [31m114[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/GMT0  |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Greenwich |    Bin [31m114[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/HST   |    Bin [31m329[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Hongkong  |    Bin [31m1233[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Iceland   |    Bin [31m148[m -> [32m0[m bytes
 .../pytz/zoneinfo/Indian/Antananarivo              |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Chagos  |    Bin [31m185[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Indian/Christmas   |    Bin [31m185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Cocos   |    Bin [31m254[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Comoro  |    Bin [31m265[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Indian/Kerguelen   |    Bin [31m185[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Mahe    |    Bin [31m151[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Indian/Maldives    |    Bin [31m185[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Indian/Mauritius   |    Bin [31m227[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Mayotte |    Bin [31m265[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Indian/Reunion |    Bin [31m151[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Iran  |    Bin [31m1248[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Israel    |    Bin [31m2388[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Jamaica   |    Bin [31m482[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Japan |    Bin [31m309[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Kwajalein |    Bin [31m302[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Libya |    Bin [31m625[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/MET   |    Bin [31m2933[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/MST   |    Bin [31m360[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/MST7MDT   |    Bin [31m2460[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Mexico/BajaNorte   |    Bin [31m2458[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Mexico/BajaSur |    Bin [31m1060[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Mexico/General |    Bin [31m1222[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/NZ    |    Bin [31m2437[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/NZ-CHAT   |    Bin [31m2054[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Navajo    |    Bin [31m2460[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/PRC   |    Bin [31m561[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/PST8PDT   |    Bin [31m2852[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Apia   |    Bin [31m598[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Auckland   |    Bin [31m2437[m -> [32m0[m bytes
 .../pytz/zoneinfo/Pacific/Bougainville             |    Bin [31m254[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Chatham    |    Bin [31m2054[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Chuuk  |    Bin [31m172[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Easter |    Bin [31m2219[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Efate  |    Bin [31m524[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Enderbury  |    Bin [31m220[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Fakaofo    |    Bin [31m186[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Fiji   |    Bin [31m564[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Funafuti   |    Bin [31m152[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Galapagos  |    Bin [31m224[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Gambier    |    Bin [31m150[m -> [32m0[m bytes
 .../pytz/zoneinfo/Pacific/Guadalcanal              |    Bin [31m152[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Guam   |    Bin [31m494[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Honolulu   |    Bin [31m329[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Johnston   |    Bin [31m329[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Kanton |    Bin [31m220[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Kiritimati |    Bin [31m224[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Kosrae |    Bin [31m337[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Kwajalein  |    Bin [31m302[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Majuro |    Bin [31m152[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Marquesas  |    Bin [31m159[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Midway |    Bin [31m175[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Nauru  |    Bin [31m238[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Niue   |    Bin [31m189[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Norfolk    |    Bin [31m866[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Noumea |    Bin [31m290[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Pago_Pago  |    Bin [31m175[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Palau  |    Bin [31m166[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Pitcairn   |    Bin [31m188[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Pohnpei    |    Bin [31m152[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Ponape |    Bin [31m152[m -> [32m0[m bytes
 .../pytz/zoneinfo/Pacific/Port_Moresby             |    Bin [31m172[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Rarotonga  |    Bin [31m589[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Saipan |    Bin [31m494[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Samoa  |    Bin [31m175[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Tahiti |    Bin [31m151[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Tarawa |    Bin [31m152[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/Pacific/Tongatapu  |    Bin [31m358[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Truk   |    Bin [31m172[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Wake   |    Bin [31m152[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Wallis |    Bin [31m152[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/Pacific/Yap    |    Bin [31m172[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Poland    |    Bin [31m2654[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Portugal  |    Bin [31m3527[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/ROC   |    Bin [31m761[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/ROK   |    Bin [31m617[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Singapore |    Bin [31m401[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Turkey    |    Bin [31m1933[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/UCT   |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/US/Alaska |    Bin [31m2371[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Aleutian    |    Bin [31m2356[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Arizona     |    Bin [31m360[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Central     |    Bin [31m3592[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/US/East-Indiana    |    Bin [31m1682[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Eastern     |    Bin [31m3552[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/US/Hawaii |    Bin [31m329[m -> [32m0[m bytes
 .../site-packages/pytz/zoneinfo/US/Indiana-Starke  |    Bin [31m2444[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Michigan    |    Bin [31m2230[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Mountain    |    Bin [31m2460[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/US/Pacific     |    Bin [31m2852[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/US/Samoa  |    Bin [31m175[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/UTC   |    Bin [31m114[m -> [32m0[m bytes
 .../venv/Lib/site-packages/pytz/zoneinfo/Universal |    Bin [31m114[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/W-SU  |    Bin [31m1535[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/WET   |    Bin [31m3527[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/pytz/zoneinfo/Zulu  |    Bin [31m114[m -> [32m0[m bytes
 .../Lib/site-packages/pytz/zoneinfo/iso3166.tab    |    279 [31m-[m
 .../Lib/site-packages/pytz/zoneinfo/leapseconds    |     79 [31m-[m
 .../venv/Lib/site-packages/pytz/zoneinfo/tzdata.zi |   4300 [31m-[m
 .../venv/Lib/site-packages/pytz/zoneinfo/zone.tab  |    448 [31m-[m
 .../Lib/site-packages/pytz/zoneinfo/zone1970.tab   |    375 [31m-[m
 .../Lib/site-packages/pytz/zoneinfo/zonenow.tab    |    296 [31m-[m
 .../site-packages/pyyaml-6.0.3.dist-info/INSTALLER |      1 [31m-[m
 .../site-packages/pyyaml-6.0.3.dist-info/METADATA  |     59 [31m-[m
 .../site-packages/pyyaml-6.0.3.dist-info/RECORD    |     43 [31m-[m
 .../Lib/site-packages/pyyaml-6.0.3.dist-info/WHEEL |      5 [31m-[m
 .../pyyaml-6.0.3.dist-info/licenses/LICENSE        |     20 [31m-[m
 .../pyyaml-6.0.3.dist-info/top_level.txt           |      2 [31m-[m
 .../site-packages/redis-7.1.0.dist-info/INSTALLER  |      1 [31m-[m
 .../site-packages/redis-7.1.0.dist-info/METADATA   |    266 [31m-[m
 .../Lib/site-packages/redis-7.1.0.dist-info/RECORD |    213 [31m-[m
 .../site-packages/redis-7.1.0.dist-info/REQUESTED  |      0
 .../Lib/site-packages/redis-7.1.0.dist-info/WHEEL  |      4 [31m-[m
 .../redis-7.1.0.dist-info/licenses/LICENSE         |     21 [31m-[m
 backend/venv/Lib/site-packages/redis/__init__.py   |     89 [31m-[m
 .../redis/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1995[m -> [32m0[m bytes
 .../redis/__pycache__/background.cpython-312.pyc   |    Bin [31m9456[m -> [32m0[m bytes
 .../redis/__pycache__/backoff.cpython-312.pyc      |    Bin [31m9854[m -> [32m0[m bytes
 .../redis/__pycache__/cache.cpython-312.pyc        |    Bin [31m17732[m -> [32m0[m bytes
 .../redis/__pycache__/client.cpython-312.pyc       |    Bin [31m73260[m -> [32m0[m bytes
 .../redis/__pycache__/cluster.cpython-312.pyc      |    Bin [31m136838[m -> [32m0[m bytes
 .../redis/__pycache__/connection.cpython-312.pyc   |    Bin [31m124426[m -> [32m0[m bytes
 .../redis/__pycache__/crc.cpython-312.pyc          |    Bin [31m970[m -> [32m0[m bytes
 .../redis/__pycache__/credentials.cpython-312.pyc  |    Bin [31m3677[m -> [32m0[m bytes
 .../__pycache__/data_structure.cpython-312.pyc     |    Bin [31m4678[m -> [32m0[m bytes
 .../redis/__pycache__/event.cpython-312.pyc        |    Bin [31m25371[m -> [32m0[m bytes
 .../redis/__pycache__/exceptions.cpython-312.pyc   |    Bin [31m10152[m -> [32m0[m bytes
 .../redis/__pycache__/lock.cpython-312.pyc         |    Bin [31m14481[m -> [32m0[m bytes
 .../maint_notifications.cpython-312.pyc            |    Bin [31m33212[m -> [32m0[m bytes
 .../redis/__pycache__/ocsp.cpython-312.pyc         |    Bin [31m15059[m -> [32m0[m bytes
 .../redis/__pycache__/retry.cpython-312.pyc        |    Bin [31m5574[m -> [32m0[m bytes
 .../redis/__pycache__/sentinel.cpython-312.pyc     |    Bin [31m18744[m -> [32m0[m bytes
 .../redis/__pycache__/typing.cpython-312.pyc       |    Bin [31m2072[m -> [32m0[m bytes
 .../redis/__pycache__/utils.cpython-312.pyc        |    Bin [31m16983[m -> [32m0[m bytes
 .../Lib/site-packages/redis/_parsers/__init__.py   |     27 [31m-[m
 .../_parsers/__pycache__/__init__.cpython-312.pyc  |    Bin [31m754[m -> [32m0[m bytes
 .../_parsers/__pycache__/base.cpython-312.pyc      |    Bin [31m19468[m -> [32m0[m bytes
 .../_parsers/__pycache__/commands.cpython-312.pyc  |    Bin [31m22409[m -> [32m0[m bytes
 .../_parsers/__pycache__/encoders.cpython-312.pyc  |    Bin [31m2277[m -> [32m0[m bytes
 .../_parsers/__pycache__/helpers.cpython-312.pyc   |    Bin [31m40705[m -> [32m0[m bytes
 .../_parsers/__pycache__/hiredis.cpython-312.pyc   |    Bin [31m12649[m -> [32m0[m bytes
 .../_parsers/__pycache__/resp2.cpython-312.pyc     |    Bin [31m5036[m -> [32m0[m bytes
 .../_parsers/__pycache__/resp3.cpython-312.pyc     |    Bin [31m9255[m -> [32m0[m bytes
 .../_parsers/__pycache__/socket.cpython-312.pyc    |    Bin [31m7171[m -> [32m0[m bytes
 .../venv/Lib/site-packages/redis/_parsers/base.py  |    474 [31m-[m
 .../Lib/site-packages/redis/_parsers/commands.py   |    692 [31m-[m
 .../Lib/site-packages/redis/_parsers/encoders.py   |     44 [31m-[m
 .../Lib/site-packages/redis/_parsers/helpers.py    |    946 [31m-[m
 .../Lib/site-packages/redis/_parsers/hiredis.py    |    301 [31m-[m
 .../venv/Lib/site-packages/redis/_parsers/resp2.py |    132 [31m-[m
 .../venv/Lib/site-packages/redis/_parsers/resp3.py |    263 [31m-[m
 .../Lib/site-packages/redis/_parsers/socket.py     |    162 [31m-[m
 .../Lib/site-packages/redis/asyncio/__init__.py    |     64 [31m-[m
 .../asyncio/__pycache__/__init__.cpython-312.pyc   |    Bin [31m1358[m -> [32m0[m bytes
 .../asyncio/__pycache__/client.cpython-312.pyc     |    Bin [31m75624[m -> [32m0[m bytes
 .../asyncio/__pycache__/cluster.cpython-312.pyc    |    Bin [31m111266[m -> [32m0[m bytes
 .../asyncio/__pycache__/connection.cpython-312.pyc |    Bin [31m67672[m -> [32m0[m bytes
 .../redis/asyncio/__pycache__/lock.cpython-312.pyc |    Bin [31m15316[m -> [32m0[m bytes
 .../asyncio/__pycache__/retry.cpython-312.pyc      |    Bin [31m3066[m -> [32m0[m bytes
 .../asyncio/__pycache__/sentinel.cpython-312.pyc   |    Bin [31m18932[m -> [32m0[m bytes
 .../asyncio/__pycache__/utils.cpython-312.pyc      |    Bin [31m1554[m -> [32m0[m bytes
 .../venv/Lib/site-packages/redis/asyncio/client.py |   1675 [31m-[m
 .../Lib/site-packages/redis/asyncio/cluster.py     |   2583 [31m-[m
 .../Lib/site-packages/redis/asyncio/connection.py  |   1399 [31m-[m
 .../site-packages/redis/asyncio/http/__init__.py   |      0
 .../http/__pycache__/__init__.cpython-312.pyc      |    Bin [31m180[m -> [32m0[m bytes
 .../http/__pycache__/http_client.cpython-312.pyc   |    Bin [31m9646[m -> [32m0[m bytes
 .../redis/asyncio/http/http_client.py              |    265 [31m-[m
 .../venv/Lib/site-packages/redis/asyncio/lock.py   |    334 [31m-[m
 .../redis/asyncio/multidb/__init__.py              |      0
 .../multidb/__pycache__/__init__.cpython-312.pyc   |    Bin [31m183[m -> [32m0[m bytes
 .../multidb/__pycache__/client.cpython-312.pyc     |    Bin [31m27268[m -> [32m0[m bytes
 .../__pycache__/command_executor.cpython-312.pyc   |    Bin [31m18696[m -> [32m0[m bytes
 .../multidb/__pycache__/config.cpython-312.pyc     |    Bin [31m10027[m -> [32m0[m bytes
 .../multidb/__pycache__/database.cpython-312.pyc   |    Bin [31m3396[m -> [32m0[m bytes
 .../multidb/__pycache__/event.cpython-312.pyc      |    Bin [31m5150[m -> [32m0[m bytes
 .../multidb/__pycache__/failover.cpython-312.pyc   |    Bin [31m6292[m -> [32m0[m bytes
 .../__pycache__/healthcheck.cpython-312.pyc        |    Bin [31m13432[m -> [32m0[m bytes
 .../site-packages/redis/asyncio/multidb/client.py  |    532 [31m-[m
 .../redis/asyncio/multidb/command_executor.py      |    339 [31m-[m
 .../site-packages/redis/asyncio/multidb/config.py  |    210 [31m-[m
 .../redis/asyncio/multidb/database.py              |     69 [31m-[m
 .../site-packages/redis/asyncio/multidb/event.py   |     84 [31m-[m
 .../redis/asyncio/multidb/failover.py              |    125 [31m-[m
 .../redis/asyncio/multidb/failure_detector.py      |     38 [31m-[m
 .../redis/asyncio/multidb/healthcheck.py           |    285 [31m-[m
 .../venv/Lib/site-packages/redis/asyncio/retry.py  |     58 [31m-[m
 .../Lib/site-packages/redis/asyncio/sentinel.py    |    404 [31m-[m
 .../venv/Lib/site-packages/redis/asyncio/utils.py  |     28 [31m-[m
 .../venv/Lib/site-packages/redis/auth/__init__.py  |      0
 .../auth/__pycache__/__init__.cpython-312.pyc      |    Bin [31m172[m -> [32m0[m bytes
 .../redis/auth/__pycache__/err.cpython-312.pyc     |    Bin [31m1708[m -> [32m0[m bytes
 .../redis/auth/__pycache__/idp.cpython-312.pyc     |    Bin [31m1306[m -> [32m0[m bytes
 .../redis/auth/__pycache__/token.cpython-312.pyc   |    Bin [31m7502[m -> [32m0[m bytes
 .../auth/__pycache__/token_manager.cpython-312.pyc |    Bin [31m18025[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/redis/auth/err.py   |     31 [31m-[m
 backend/venv/Lib/site-packages/redis/auth/idp.py   |     28 [31m-[m
 backend/venv/Lib/site-packages/redis/auth/token.py |    130 [31m-[m
 .../Lib/site-packages/redis/auth/token_manager.py  |    370 [31m-[m
 backend/venv/Lib/site-packages/redis/background.py |    204 [31m-[m
 backend/venv/Lib/site-packages/redis/backoff.py    |    183 [31m-[m
 backend/venv/Lib/site-packages/redis/cache.py      |    415 [31m-[m
 backend/venv/Lib/site-packages/redis/client.py     |   1717 [31m-[m
 backend/venv/Lib/site-packages/redis/cluster.py    |   3601 [31m-[m
 .../Lib/site-packages/redis/commands/__init__.py   |     18 [31m-[m
 .../commands/__pycache__/__init__.cpython-312.pyc  |    Bin [31m659[m -> [32m0[m bytes
 .../commands/__pycache__/cluster.cpython-312.pyc   |    Bin [31m35484[m -> [32m0[m bytes
 .../commands/__pycache__/core.cpython-312.pyc      |    Bin [31m284864[m -> [32m0[m bytes
 .../commands/__pycache__/helpers.cpython-312.pyc   |    Bin [31m5213[m -> [32m0[m bytes
 .../commands/__pycache__/policies.cpython-312.pyc  |    Bin [31m12689[m -> [32m0[m bytes
 .../__pycache__/redismodules.cpython-312.pyc       |    Bin [31m3765[m -> [32m0[m bytes
 .../commands/__pycache__/sentinel.cpython-312.pyc  |    Bin [31m7083[m -> [32m0[m bytes
 .../site-packages/redis/commands/bf/__init__.py    |    253 [31m-[m
 .../bf/__pycache__/__init__.cpython-312.pyc        |    Bin [31m9367[m -> [32m0[m bytes
 .../bf/__pycache__/commands.cpython-312.pyc        |    Bin [31m26506[m -> [32m0[m bytes
 .../commands/bf/__pycache__/info.cpython-312.pyc   |    Bin [31m5585[m -> [32m0[m bytes
 .../site-packages/redis/commands/bf/commands.py    |    538 [31m-[m
 .../Lib/site-packages/redis/commands/bf/info.py    |    120 [31m-[m
 .../Lib/site-packages/redis/commands/cluster.py    |    983 [31m-[m
 .../venv/Lib/site-packages/redis/commands/core.py  |   6988 [31m-[m
 .../Lib/site-packages/redis/commands/helpers.py    |    117 [31m-[m
 .../site-packages/redis/commands/json/__init__.py  |    147 [31m-[m
 .../json/__pycache__/__init__.cpython-312.pyc      |    Bin [31m6933[m -> [32m0[m bytes
 .../json/__pycache__/_util.cpython-312.pyc         |    Bin [31m373[m -> [32m0[m bytes
 .../json/__pycache__/commands.cpython-312.pyc      |    Bin [31m19908[m -> [32m0[m bytes
 .../json/__pycache__/decoders.cpython-312.pyc      |    Bin [31m2427[m -> [32m0[m bytes
 .../commands/json/__pycache__/path.cpython-312.pyc |    Bin [31m978[m -> [32m0[m bytes
 .../Lib/site-packages/redis/commands/json/_util.py |      5 [31m-[m
 .../site-packages/redis/commands/json/commands.py  |    431 [31m-[m
 .../site-packages/redis/commands/json/decoders.py  |     60 [31m-[m
 .../Lib/site-packages/redis/commands/json/path.py  |     16 [31m-[m
 .../Lib/site-packages/redis/commands/policies.py   |    330 [31m-[m
 .../site-packages/redis/commands/redismodules.py   |    101 [31m-[m
 .../redis/commands/search/__init__.py              |    191 [31m-[m
 .../search/__pycache__/__init__.cpython-312.pyc    |    Bin [31m7265[m -> [32m0[m bytes
 .../search/__pycache__/_util.cpython-312.pyc       |    Bin [31m519[m -> [32m0[m bytes
 .../search/__pycache__/aggregation.cpython-312.pyc |    Bin [31m16315[m -> [32m0[m bytes
 .../search/__pycache__/commands.cpython-312.pyc    |    Bin [31m48690[m -> [32m0[m bytes
 .../search/__pycache__/dialect.cpython-312.pyc     |    Bin [31m212[m -> [32m0[m bytes
 .../search/__pycache__/document.cpython-312.pyc    |    Bin [31m1121[m -> [32m0[m bytes
 .../search/__pycache__/field.cpython-312.pyc       |    Bin [31m8824[m -> [32m0[m bytes
 .../__pycache__/hybrid_query.cpython-312.pyc       |    Bin [31m18336[m -> [32m0[m bytes
 .../__pycache__/hybrid_result.cpython-312.pyc      |    Bin [31m1573[m -> [32m0[m bytes
 .../__pycache__/index_definition.cpython-312.pyc   |    Bin [31m4271[m -> [32m0[m bytes
 .../profile_information.cpython-312.pyc            |    Bin [31m877[m -> [32m0[m bytes
 .../search/__pycache__/query.cpython-312.pyc       |    Bin [31m16515[m -> [32m0[m bytes
 .../search/__pycache__/querystring.cpython-312.pyc |    Bin [31m14074[m -> [32m0[m bytes
 .../search/__pycache__/reducers.cpython-312.pyc    |    Bin [31m7662[m -> [32m0[m bytes
 .../search/__pycache__/result.cpython-312.pyc      |    Bin [31m2892[m -> [32m0[m bytes
 .../search/__pycache__/suggestion.cpython-312.pyc  |    Bin [31m2840[m -> [32m0[m bytes
 .../site-packages/redis/commands/search/_util.py   |      7 [31m-[m
 .../redis/commands/search/aggregation.py           |    399 [31m-[m
 .../redis/commands/search/commands.py              |   1297 [31m-[m
 .../site-packages/redis/commands/search/dialect.py |      3 [31m-[m
 .../redis/commands/search/document.py              |     17 [31m-[m
 .../site-packages/redis/commands/search/field.py   |    210 [31m-[m
 .../redis/commands/search/hybrid_query.py          |    383 [31m-[m
 .../redis/commands/search/hybrid_result.py         |     27 [31m-[m
 .../redis/commands/search/index_definition.py      |     79 [31m-[m
 .../redis/commands/search/profile_information.py   |     14 [31m-[m
 .../site-packages/redis/commands/search/query.py   |    381 [31m-[m
 .../redis/commands/search/querystring.py           |    317 [31m-[m
 .../redis/commands/search/reducers.py              |    182 [31m-[m
 .../site-packages/redis/commands/search/result.py  |     87 [31m-[m
 .../redis/commands/search/suggestion.py            |     55 [31m-[m
 .../Lib/site-packages/redis/commands/sentinel.py   |    129 [31m-[m
 .../redis/commands/timeseries/__init__.py          |    108 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m4694[m -> [32m0[m bytes
 .../__pycache__/commands.cpython-312.pyc           |    Bin [31m49787[m -> [32m0[m bytes
 .../timeseries/__pycache__/info.cpython-312.pyc    |    Bin [31m4149[m -> [32m0[m bytes
 .../timeseries/__pycache__/utils.cpython-312.pyc   |    Bin [31m2633[m -> [32m0[m bytes
 .../redis/commands/timeseries/commands.py          |   1136 [31m-[m
 .../redis/commands/timeseries/info.py              |     91 [31m-[m
 .../redis/commands/timeseries/utils.py             |     44 [31m-[m
 .../redis/commands/vectorset/__init__.py           |     46 [31m-[m
 .../vectorset/__pycache__/__init__.cpython-312.pyc |    Bin [31m2241[m -> [32m0[m bytes
 .../vectorset/__pycache__/commands.cpython-312.pyc |    Bin [31m15908[m -> [32m0[m bytes
 .../vectorset/__pycache__/utils.cpython-312.pyc    |    Bin [31m4751[m -> [32m0[m bytes
 .../redis/commands/vectorset/commands.py           |    392 [31m-[m
 .../redis/commands/vectorset/utils.py              |    130 [31m-[m
 backend/venv/Lib/site-packages/redis/connection.py |   3001 [31m-[m
 backend/venv/Lib/site-packages/redis/crc.py        |     23 [31m-[m
 .../venv/Lib/site-packages/redis/credentials.py    |     65 [31m-[m
 .../venv/Lib/site-packages/redis/data_structure.py |     81 [31m-[m
 backend/venv/Lib/site-packages/redis/event.py      |    468 [31m-[m
 backend/venv/Lib/site-packages/redis/exceptions.py |    263 [31m-[m
 .../venv/Lib/site-packages/redis/http/__init__.py  |      0
 .../http/__pycache__/__init__.cpython-312.pyc      |    Bin [31m172[m -> [32m0[m bytes
 .../http/__pycache__/http_client.cpython-312.pyc   |    Bin [31m17290[m -> [32m0[m bytes
 .../Lib/site-packages/redis/http/http_client.py    |    425 [31m-[m
 backend/venv/Lib/site-packages/redis/lock.py       |    343 [31m-[m
 .../Lib/site-packages/redis/maint_notifications.py |    810 [31m-[m
 .../Lib/site-packages/redis/multidb/__init__.py    |      0
 .../multidb/__pycache__/__init__.cpython-312.pyc   |    Bin [31m175[m -> [32m0[m bytes
 .../multidb/__pycache__/circuit.cpython-312.pyc    |    Bin [31m7245[m -> [32m0[m bytes
 .../multidb/__pycache__/client.cpython-312.pyc     |    Bin [31m24978[m -> [32m0[m bytes
 .../__pycache__/command_executor.cpython-312.pyc   |    Bin [31m18439[m -> [32m0[m bytes
 .../multidb/__pycache__/config.cpython-312.pyc     |    Bin [31m9980[m -> [32m0[m bytes
 .../multidb/__pycache__/database.cpython-312.pyc   |    Bin [31m6285[m -> [32m0[m bytes
 .../multidb/__pycache__/event.cpython-312.pyc      |    Bin [31m5226[m -> [32m0[m bytes
 .../multidb/__pycache__/exception.cpython-312.pyc  |    Bin [31m1238[m -> [32m0[m bytes
 .../multidb/__pycache__/failover.cpython-312.pyc   |    Bin [31m6144[m -> [32m0[m bytes
 .../__pycache__/failure_detector.cpython-312.pyc   |    Bin [31m5993[m -> [32m0[m bytes
 .../__pycache__/healthcheck.cpython-312.pyc        |    Bin [31m12531[m -> [32m0[m bytes
 .../Lib/site-packages/redis/multidb/circuit.py     |    144 [31m-[m
 .../venv/Lib/site-packages/redis/multidb/client.py |    533 [31m-[m
 .../redis/multidb/command_executor.py              |    350 [31m-[m
 .../venv/Lib/site-packages/redis/multidb/config.py |    207 [31m-[m
 .../Lib/site-packages/redis/multidb/database.py    |    130 [31m-[m
 .../venv/Lib/site-packages/redis/multidb/event.py  |     89 [31m-[m
 .../Lib/site-packages/redis/multidb/exception.py   |     17 [31m-[m
 .../Lib/site-packages/redis/multidb/failover.py    |    125 [31m-[m
 .../redis/multidb/failure_detector.py              |    104 [31m-[m
 .../Lib/site-packages/redis/multidb/healthcheck.py |    282 [31m-[m
 backend/venv/Lib/site-packages/redis/ocsp.py       |    308 [31m-[m
 backend/venv/Lib/site-packages/redis/py.typed      |      0
 backend/venv/Lib/site-packages/redis/retry.py      |    126 [31m-[m
 backend/venv/Lib/site-packages/redis/sentinel.py   |    425 [31m-[m
 backend/venv/Lib/site-packages/redis/typing.py     |     57 [31m-[m
 backend/venv/Lib/site-packages/redis/utils.py      |    421 [31m-[m
 .../requests-2.32.5.dist-info/INSTALLER            |      1 [31m-[m
 .../requests-2.32.5.dist-info/METADATA             |    133 [31m-[m
 .../site-packages/requests-2.32.5.dist-info/RECORD |     42 [31m-[m
 .../site-packages/requests-2.32.5.dist-info/WHEEL  |      5 [31m-[m
 .../requests-2.32.5.dist-info/licenses/LICENSE     |    175 [31m-[m
 .../requests-2.32.5.dist-info/top_level.txt        |      1 [31m-[m
 .../venv/Lib/site-packages/requests/__init__.py    |    184 [31m-[m
 .../requests/__pycache__/__init__.cpython-312.pyc  |    Bin [31m5399[m -> [32m0[m bytes
 .../__pycache__/__version__.cpython-312.pyc        |    Bin [31m563[m -> [32m0[m bytes
 .../__pycache__/_internal_utils.cpython-312.pyc    |    Bin [31m2003[m -> [32m0[m bytes
 .../requests/__pycache__/adapters.cpython-312.pyc  |    Bin [31m27784[m -> [32m0[m bytes
 .../requests/__pycache__/api.cpython-312.pyc       |    Bin [31m7170[m -> [32m0[m bytes
 .../requests/__pycache__/auth.cpython-312.pyc      |    Bin [31m13900[m -> [32m0[m bytes
 .../requests/__pycache__/certs.cpython-312.pyc     |    Bin [31m645[m -> [32m0[m bytes
 .../requests/__pycache__/compat.cpython-312.pyc    |    Bin [31m2354[m -> [32m0[m bytes
 .../requests/__pycache__/cookies.cpython-312.pyc   |    Bin [31m25177[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m7564[m -> [32m0[m bytes
 .../requests/__pycache__/help.cpython-312.pyc      |    Bin [31m4306[m -> [32m0[m bytes
 .../requests/__pycache__/hooks.cpython-312.pyc     |    Bin [31m1030[m -> [32m0[m bytes
 .../requests/__pycache__/models.cpython-312.pyc    |    Bin [31m35430[m -> [32m0[m bytes
 .../requests/__pycache__/packages.cpython-312.pyc  |    Bin [31m1097[m -> [32m0[m bytes
 .../requests/__pycache__/sessions.cpython-312.pyc  |    Bin [31m27833[m -> [32m0[m bytes
 .../__pycache__/status_codes.cpython-312.pyc       |    Bin [31m6002[m -> [32m0[m bytes
 .../__pycache__/structures.cpython-312.pyc         |    Bin [31m5602[m -> [32m0[m bytes
 .../requests/__pycache__/utils.cpython-312.pyc     |    Bin [31m36081[m -> [32m0[m bytes
 .../venv/Lib/site-packages/requests/__version__.py |     14 [31m-[m
 .../Lib/site-packages/requests/_internal_utils.py  |     50 [31m-[m
 .../venv/Lib/site-packages/requests/adapters.py    |    696 [31m-[m
 backend/venv/Lib/site-packages/requests/api.py     |    157 [31m-[m
 backend/venv/Lib/site-packages/requests/auth.py    |    314 [31m-[m
 backend/venv/Lib/site-packages/requests/certs.py   |     17 [31m-[m
 backend/venv/Lib/site-packages/requests/compat.py  |    106 [31m-[m
 backend/venv/Lib/site-packages/requests/cookies.py |    561 [31m-[m
 .../venv/Lib/site-packages/requests/exceptions.py  |    151 [31m-[m
 backend/venv/Lib/site-packages/requests/help.py    |    134 [31m-[m
 backend/venv/Lib/site-packages/requests/hooks.py   |     33 [31m-[m
 backend/venv/Lib/site-packages/requests/models.py  |   1039 [31m-[m
 .../venv/Lib/site-packages/requests/packages.py    |     23 [31m-[m
 .../venv/Lib/site-packages/requests/sessions.py    |    831 [31m-[m
 .../Lib/site-packages/requests/status_codes.py     |    128 [31m-[m
 .../venv/Lib/site-packages/requests/structures.py  |     99 [31m-[m
 backend/venv/Lib/site-packages/requests/utils.py   |   1086 [31m-[m
 .../Lib/site-packages/rq-2.6.1.dist-info/INSTALLER |      1 [31m-[m
 .../Lib/site-packages/rq-2.6.1.dist-info/METADATA  |    317 [31m-[m
 .../Lib/site-packages/rq-2.6.1.dist-info/RECORD    |     85 [31m-[m
 .../Lib/site-packages/rq-2.6.1.dist-info/REQUESTED |      0
 .../Lib/site-packages/rq-2.6.1.dist-info/WHEEL     |      4 [31m-[m
 .../rq-2.6.1.dist-info/entry_points.txt            |      4 [31m-[m
 .../rq-2.6.1.dist-info/licenses/LICENSE            |     26 [31m-[m
 backend/venv/Lib/site-packages/rq/__init__.py      |     21 [31m-[m
 .../rq/__pycache__/__init__.cpython-312.pyc        |    Bin [31m591[m -> [32m0[m bytes
 .../rq/__pycache__/command.cpython-312.pyc         |    Bin [31m5819[m -> [32m0[m bytes
 .../rq/__pycache__/connections.cpython-312.pyc     |    Bin [31m1012[m -> [32m0[m bytes
 .../rq/__pycache__/cron.cpython-312.pyc            |    Bin [31m27330[m -> [32m0[m bytes
 .../cron_scheduler_registry.cpython-312.pyc        |    Bin [31m3869[m -> [32m0[m bytes
 .../rq/__pycache__/decorators.cpython-312.pyc      |    Bin [31m5763[m -> [32m0[m bytes
 .../rq/__pycache__/defaults.cpython-312.pyc        |    Bin [31m1093[m -> [32m0[m bytes
 .../rq/__pycache__/dependency.cpython-312.pyc      |    Bin [31m1588[m -> [32m0[m bytes
 .../rq/__pycache__/exceptions.cpython-312.pyc      |    Bin [31m2451[m -> [32m0[m bytes
 .../rq/__pycache__/executions.cpython-312.pyc      |    Bin [31m10967[m -> [32m0[m bytes
 .../rq/__pycache__/group.cpython-312.pyc           |    Bin [31m7830[m -> [32m0[m bytes
 .../__pycache__/intermediate_queue.cpython-312.pyc |    Bin [31m5361[m -> [32m0[m bytes
 .../rq/__pycache__/job.cpython-312.pyc             |    Bin [31m86365[m -> [32m0[m bytes
 .../rq/__pycache__/local.cpython-312.pyc           |    Bin [31m20983[m -> [32m0[m bytes
 .../rq/__pycache__/logutils.cpython-312.pyc        |    Bin [31m7685[m -> [32m0[m bytes
 .../rq/__pycache__/maintenance.cpython-312.pyc     |    Bin [31m1343[m -> [32m0[m bytes
 .../rq/__pycache__/queue.cpython-312.pyc           |    Bin [31m62809[m -> [32m0[m bytes
 .../rq/__pycache__/registry.cpython-312.pyc        |    Bin [31m31723[m -> [32m0[m bytes
 .../rq/__pycache__/repeat.cpython-312.pyc          |    Bin [31m5069[m -> [32m0[m bytes
 .../rq/__pycache__/results.cpython-312.pyc         |    Bin [31m10505[m -> [32m0[m bytes
 .../rq/__pycache__/scheduler.cpython-312.pyc       |    Bin [31m12509[m -> [32m0[m bytes
 .../rq/__pycache__/serializers.cpython-312.pyc     |    Bin [31m3188[m -> [32m0[m bytes
 .../rq/__pycache__/suspension.cpython-312.pyc      |    Bin [31m1998[m -> [32m0[m bytes
 .../rq/__pycache__/timeouts.cpython-312.pyc        |    Bin [31m6896[m -> [32m0[m bytes
 .../rq/__pycache__/types.cpython-312.pyc           |    Bin [31m871[m -> [32m0[m bytes
 .../rq/__pycache__/utils.cpython-312.pyc           |    Bin [31m22681[m -> [32m0[m bytes
 .../rq/__pycache__/version.cpython-312.pyc         |    Bin [31m185[m -> [32m0[m bytes
 .../rq/__pycache__/worker.cpython-312.pyc          |    Bin [31m95894[m -> [32m0[m bytes
 .../rq/__pycache__/worker_pool.cpython-312.pyc     |    Bin [31m13816[m -> [32m0[m bytes
 .../worker_registration.cpython-312.pyc            |    Bin [31m4275[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/rq/cli/__init__.py  |      8 [31m-[m
 backend/venv/Lib/site-packages/rq/cli/__main__.py  |      6 [31m-[m
 .../rq/cli/__pycache__/__init__.cpython-312.pyc    |    Bin [31m310[m -> [32m0[m bytes
 .../rq/cli/__pycache__/__main__.cpython-312.pyc    |    Bin [31m334[m -> [32m0[m bytes
 .../rq/cli/__pycache__/cli.cpython-312.pyc         |    Bin [31m11346[m -> [32m0[m bytes
 .../rq/cli/__pycache__/cli_cron.cpython-312.pyc    |    Bin [31m2168[m -> [32m0[m bytes
 .../rq/cli/__pycache__/helpers.cpython-312.pyc     |    Bin [31m19962[m -> [32m0[m bytes
 .../rq/cli/__pycache__/workers.cpython-312.pyc     |    Bin [31m9274[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/rq/cli/cli.py       |    270 [31m-[m
 backend/venv/Lib/site-packages/rq/cli/cli_cron.py  |     53 [31m-[m
 backend/venv/Lib/site-packages/rq/cli/helpers.py   |    440 [31m-[m
 backend/venv/Lib/site-packages/rq/cli/workers.py   |    228 [31m-[m
 backend/venv/Lib/site-packages/rq/command.py       |    143 [31m-[m
 backend/venv/Lib/site-packages/rq/connections.py   |     13 [31m-[m
 .../venv/Lib/site-packages/rq/contrib/__init__.py  |      0
 .../contrib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m172[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/rq/cron.py          |    569 [31m-[m
 .../site-packages/rq/cron_scheduler_registry.py    |     94 [31m-[m
 backend/venv/Lib/site-packages/rq/decorators.py    |    124 [31m-[m
 backend/venv/Lib/site-packages/rq/defaults.py      |    102 [31m-[m
 backend/venv/Lib/site-packages/rq/dependency.py    |     27 [31m-[m
 backend/venv/Lib/site-packages/rq/exceptions.py    |     52 [31m-[m
 backend/venv/Lib/site-packages/rq/executions.py    |    171 [31m-[m
 backend/venv/Lib/site-packages/rq/group.py         |    128 [31m-[m
 .../Lib/site-packages/rq/intermediate_queue.py     |    117 [31m-[m
 backend/venv/Lib/site-packages/rq/job.py           |   1779 [31m-[m
 backend/venv/Lib/site-packages/rq/local.py         |    432 [31m-[m
 backend/venv/Lib/site-packages/rq/logutils.py      |    158 [31m-[m
 backend/venv/Lib/site-packages/rq/maintenance.py   |     26 [31m-[m
 backend/venv/Lib/site-packages/rq/py.typed         |      0
 backend/venv/Lib/site-packages/rq/queue.py         |   1486 [31m-[m
 backend/venv/Lib/site-packages/rq/registry.py      |    627 [31m-[m
 backend/venv/Lib/site-packages/rq/repeat.py        |    116 [31m-[m
 backend/venv/Lib/site-packages/rq/results.py       |    228 [31m-[m
 backend/venv/Lib/site-packages/rq/scheduler.py     |    230 [31m-[m
 backend/venv/Lib/site-packages/rq/serializers.py   |     54 [31m-[m
 backend/venv/Lib/site-packages/rq/suspension.py    |     49 [31m-[m
 backend/venv/Lib/site-packages/rq/timeouts.py      |    131 [31m-[m
 backend/venv/Lib/site-packages/rq/types.py         |     26 [31m-[m
 backend/venv/Lib/site-packages/rq/utils.py         |    557 [31m-[m
 backend/venv/Lib/site-packages/rq/version.py       |      1 [31m-[m
 backend/venv/Lib/site-packages/rq/worker.py        |   1861 [31m-[m
 backend/venv/Lib/site-packages/rq/worker_pool.py   |    276 [31m-[m
 .../Lib/site-packages/rq/worker_registration.py    |    104 [31m-[m
 .../site-packages/rsa-4.9.1.dist-info/INSTALLER    |      1 [31m-[m
 .../Lib/site-packages/rsa-4.9.1.dist-info/LICENSE  |     13 [31m-[m
 .../Lib/site-packages/rsa-4.9.1.dist-info/METADATA |    140 [31m-[m
 .../Lib/site-packages/rsa-4.9.1.dist-info/RECORD   |     41 [31m-[m
 .../Lib/site-packages/rsa-4.9.1.dist-info/WHEEL    |      4 [31m-[m
 .../rsa-4.9.1.dist-info/entry_points.txt           |      8 [31m-[m
 backend/venv/Lib/site-packages/rsa/__init__.py     |     60 [31m-[m
 .../rsa/__pycache__/__init__.cpython-312.pyc       |    Bin [31m1154[m -> [32m0[m bytes
 .../rsa/__pycache__/asn1.cpython-312.pyc           |    Bin [31m2199[m -> [32m0[m bytes
 .../rsa/__pycache__/cli.cpython-312.pyc            |    Bin [31m14690[m -> [32m0[m bytes
 .../rsa/__pycache__/common.cpython-312.pyc         |    Bin [31m5314[m -> [32m0[m bytes
 .../rsa/__pycache__/core.cpython-312.pyc           |    Bin [31m1741[m -> [32m0[m bytes
 .../rsa/__pycache__/key.cpython-312.pyc            |    Bin [31m35388[m -> [32m0[m bytes
 .../rsa/__pycache__/parallel.cpython-312.pyc       |    Bin [31m2653[m -> [32m0[m bytes
 .../rsa/__pycache__/pem.cpython-312.pyc            |    Bin [31m3920[m -> [32m0[m bytes
 .../rsa/__pycache__/pkcs1.cpython-312.pyc          |    Bin [31m16685[m -> [32m0[m bytes
 .../rsa/__pycache__/pkcs1_v2.cpython-312.pyc       |    Bin [31m3521[m -> [32m0[m bytes
 .../rsa/__pycache__/prime.cpython-312.pyc          |    Bin [31m4834[m -> [32m0[m bytes
 .../rsa/__pycache__/randnum.cpython-312.pyc        |    Bin [31m2334[m -> [32m0[m bytes
 .../rsa/__pycache__/transform.cpython-312.pyc      |    Bin [31m2237[m -> [32m0[m bytes
 .../rsa/__pycache__/util.cpython-312.pyc           |    Bin [31m3503[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/rsa/asn1.py         |     52 [31m-[m
 backend/venv/Lib/site-packages/rsa/cli.py          |    321 [31m-[m
 backend/venv/Lib/site-packages/rsa/common.py       |    184 [31m-[m
 backend/venv/Lib/site-packages/rsa/core.py         |     53 [31m-[m
 backend/venv/Lib/site-packages/rsa/key.py          |    858 [31m-[m
 backend/venv/Lib/site-packages/rsa/parallel.py     |     96 [31m-[m
 backend/venv/Lib/site-packages/rsa/pem.py          |    134 [31m-[m
 backend/venv/Lib/site-packages/rsa/pkcs1.py        |    485 [31m-[m
 backend/venv/Lib/site-packages/rsa/pkcs1_v2.py     |    100 [31m-[m
 backend/venv/Lib/site-packages/rsa/prime.py        |    198 [31m-[m
 backend/venv/Lib/site-packages/rsa/py.typed        |      1 [31m-[m
 backend/venv/Lib/site-packages/rsa/randnum.py      |     95 [31m-[m
 backend/venv/Lib/site-packages/rsa/transform.py    |     72 [31m-[m
 backend/venv/Lib/site-packages/rsa/util.py         |     97 [31m-[m
 .../shellingham-1.5.4.dist-info/INSTALLER          |      1 [31m-[m
 .../shellingham-1.5.4.dist-info/LICENSE            |     13 [31m-[m
 .../shellingham-1.5.4.dist-info/METADATA           |    106 [31m-[m
 .../shellingham-1.5.4.dist-info/RECORD             |     21 [31m-[m
 .../shellingham-1.5.4.dist-info/WHEEL              |      6 [31m-[m
 .../shellingham-1.5.4.dist-info/top_level.txt      |      1 [31m-[m
 .../shellingham-1.5.4.dist-info/zip-safe           |      1 [31m-[m
 .../venv/Lib/site-packages/shellingham/__init__.py |     23 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1203[m -> [32m0[m bytes
 .../shellingham/__pycache__/_core.cpython-312.pyc  |    Bin [31m595[m -> [32m0[m bytes
 .../shellingham/__pycache__/nt.cpython-312.pyc     |    Bin [31m6305[m -> [32m0[m bytes
 .../venv/Lib/site-packages/shellingham/_core.py    |     11 [31m-[m
 backend/venv/Lib/site-packages/shellingham/nt.py   |    163 [31m-[m
 .../site-packages/shellingham/posix/__init__.py    |    112 [31m-[m
 .../posix/__pycache__/__init__.cpython-312.pyc     |    Bin [31m4174[m -> [32m0[m bytes
 .../posix/__pycache__/_core.cpython-312.pyc        |    Bin [31m301[m -> [32m0[m bytes
 .../posix/__pycache__/proc.cpython-312.pyc         |    Bin [31m3800[m -> [32m0[m bytes
 .../posix/__pycache__/ps.cpython-312.pyc           |    Bin [31m2554[m -> [32m0[m bytes
 .../Lib/site-packages/shellingham/posix/_core.py   |      3 [31m-[m
 .../Lib/site-packages/shellingham/posix/proc.py    |     83 [31m-[m
 .../venv/Lib/site-packages/shellingham/posix/ps.py |     51 [31m-[m
 .../site-packages/six-1.17.0.dist-info/INSTALLER   |      1 [31m-[m
 .../Lib/site-packages/six-1.17.0.dist-info/LICENSE |     18 [31m-[m
 .../site-packages/six-1.17.0.dist-info/METADATA    |     43 [31m-[m
 .../Lib/site-packages/six-1.17.0.dist-info/RECORD  |      8 [31m-[m
 .../Lib/site-packages/six-1.17.0.dist-info/WHEEL   |      6 [31m-[m
 .../six-1.17.0.dist-info/top_level.txt             |      1 [31m-[m
 backend/venv/Lib/site-packages/six.py              |   1003 [31m-[m
 .../sniffio-1.3.1.dist-info/INSTALLER              |      1 [31m-[m
 .../site-packages/sniffio-1.3.1.dist-info/LICENSE  |      3 [31m-[m
 .../sniffio-1.3.1.dist-info/LICENSE.APACHE2        |    202 [31m-[m
 .../sniffio-1.3.1.dist-info/LICENSE.MIT            |     20 [31m-[m
 .../site-packages/sniffio-1.3.1.dist-info/METADATA |    104 [31m-[m
 .../site-packages/sniffio-1.3.1.dist-info/RECORD   |     19 [31m-[m
 .../site-packages/sniffio-1.3.1.dist-info/WHEEL    |      5 [31m-[m
 .../sniffio-1.3.1.dist-info/top_level.txt          |      1 [31m-[m
 backend/venv/Lib/site-packages/sniffio/__init__.py |     17 [31m-[m
 .../sniffio/__pycache__/__init__.cpython-312.pyc   |    Bin [31m445[m -> [32m0[m bytes
 .../sniffio/__pycache__/_impl.cpython-312.pyc      |    Bin [31m3156[m -> [32m0[m bytes
 .../sniffio/__pycache__/_version.cpython-312.pyc   |    Bin [31m197[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/sniffio/_impl.py    |     95 [31m-[m
 .../Lib/site-packages/sniffio/_tests/__init__.py   |      0
 .../_tests/__pycache__/__init__.cpython-312.pyc    |    Bin [31m176[m -> [32m0[m bytes
 .../__pycache__/test_sniffio.cpython-312.pyc       |    Bin [31m3837[m -> [32m0[m bytes
 .../site-packages/sniffio/_tests/test_sniffio.py   |     84 [31m-[m
 backend/venv/Lib/site-packages/sniffio/_version.py |      3 [31m-[m
 backend/venv/Lib/site-packages/sniffio/py.typed    |      0
 .../soupsieve-2.8.1.dist-info/INSTALLER            |      1 [31m-[m
 .../soupsieve-2.8.1.dist-info/METADATA             |    115 [31m-[m
 .../site-packages/soupsieve-2.8.1.dist-info/RECORD |     20 [31m-[m
 .../site-packages/soupsieve-2.8.1.dist-info/WHEEL  |      4 [31m-[m
 .../soupsieve-2.8.1.dist-info/licenses/LICENSE.md  |     21 [31m-[m
 .../venv/Lib/site-packages/soupsieve/__init__.py   |    168 [31m-[m
 .../venv/Lib/site-packages/soupsieve/__meta__.py   |    197 [31m-[m
 .../soupsieve/__pycache__/__init__.cpython-312.pyc |    Bin [31m6096[m -> [32m0[m bytes
 .../soupsieve/__pycache__/__meta__.cpython-312.pyc |    Bin [31m8096[m -> [32m0[m bytes
 .../__pycache__/css_match.cpython-312.pyc          |    Bin [31m63719[m -> [32m0[m bytes
 .../__pycache__/css_parser.cpython-312.pyc         |    Bin [31m50168[m -> [32m0[m bytes
 .../__pycache__/css_types.cpython-312.pyc          |    Bin [31m17339[m -> [32m0[m bytes
 .../soupsieve/__pycache__/pretty.cpython-312.pyc   |    Bin [31m5033[m -> [32m0[m bytes
 .../soupsieve/__pycache__/util.cpython-312.pyc     |    Bin [31m4696[m -> [32m0[m bytes
 .../venv/Lib/site-packages/soupsieve/css_match.py  |   1645 [31m-[m
 .../venv/Lib/site-packages/soupsieve/css_parser.py |   1318 [31m-[m
 .../venv/Lib/site-packages/soupsieve/css_types.py  |    407 [31m-[m
 backend/venv/Lib/site-packages/soupsieve/pretty.py |    139 [31m-[m
 backend/venv/Lib/site-packages/soupsieve/py.typed  |      0
 backend/venv/Lib/site-packages/soupsieve/util.py   |    117 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/INSTALLER          |      1 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/METADATA           |    243 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/RECORD             |    532 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/REQUESTED          |      0
 .../sqlalchemy-2.0.45.dist-info/WHEEL              |      5 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/licenses/LICENSE   |     19 [31m-[m
 .../sqlalchemy-2.0.45.dist-info/top_level.txt      |      1 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/__init__.py  |    283 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m9408[m -> [32m0[m bytes
 .../sqlalchemy/__pycache__/events.cpython-312.pyc  |    Bin [31m545[m -> [32m0[m bytes
 .../sqlalchemy/__pycache__/exc.cpython-312.pyc     |    Bin [31m31216[m -> [32m0[m bytes
 .../__pycache__/inspection.cpython-312.pyc         |    Bin [31m6644[m -> [32m0[m bytes
 .../sqlalchemy/__pycache__/log.cpython-312.pyc     |    Bin [31m11602[m -> [32m0[m bytes
 .../sqlalchemy/__pycache__/schema.cpython-312.pyc  |    Bin [31m2360[m -> [32m0[m bytes
 .../sqlalchemy/__pycache__/types.cpython-312.pyc   |    Bin [31m2270[m -> [32m0[m bytes
 .../sqlalchemy/connectors/__init__.py              |     18 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m584[m -> [32m0[m bytes
 .../connectors/__pycache__/aioodbc.cpython-312.pyc |    Bin [31m7826[m -> [32m0[m bytes
 .../connectors/__pycache__/asyncio.cpython-312.pyc |    Bin [31m21678[m -> [32m0[m bytes
 .../connectors/__pycache__/pyodbc.cpython-312.pyc  |    Bin [31m9619[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/connectors/aioodbc.py |    184 [31m-[m
 .../site-packages/sqlalchemy/connectors/asyncio.py |    429 [31m-[m
 .../site-packages/sqlalchemy/connectors/pyodbc.py  |    250 [31m-[m
 .../sqlalchemy/cyextension/__init__.py             |      6 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m184[m -> [32m0[m bytes
 .../cyextension/collections.cp312-win_amd64.pyd    |    Bin [31m163840[m -> [32m0[m bytes
 .../sqlalchemy/cyextension/collections.pyx         |    409 [31m-[m
 .../cyextension/immutabledict.cp312-win_amd64.pyd  |    Bin [31m68608[m -> [32m0[m bytes
 .../sqlalchemy/cyextension/immutabledict.pxd       |      8 [31m-[m
 .../sqlalchemy/cyextension/immutabledict.pyx       |    133 [31m-[m
 .../cyextension/processors.cp312-win_amd64.pyd     |    Bin [31m58880[m -> [32m0[m bytes
 .../sqlalchemy/cyextension/processors.pyx          |     68 [31m-[m
 .../cyextension/resultproxy.cp312-win_amd64.pyd    |    Bin [31m59392[m -> [32m0[m bytes
 .../sqlalchemy/cyextension/resultproxy.pyx         |    102 [31m-[m
 .../cyextension/util.cp312-win_amd64.pyd           |    Bin [31m70656[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/cyextension/util.pyx  |     90 [31m-[m
 .../site-packages/sqlalchemy/dialects/__init__.py  |     62 [31m-[m
 .../dialects/__pycache__/__init__.cpython-312.pyc  |    Bin [31m1898[m -> [32m0[m bytes
 .../dialects/__pycache__/_typing.cpython-312.pyc   |    Bin [31m1074[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/dialects/_typing.py   |     30 [31m-[m
 .../sqlalchemy/dialects/mssql/__init__.py          |     88 [31m-[m
 .../mssql/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1652[m -> [32m0[m bytes
 .../mssql/__pycache__/aioodbc.cpython-312.pyc      |    Bin [31m2393[m -> [32m0[m bytes
 .../mssql/__pycache__/base.cpython-312.pyc         |    Bin [31m153387[m -> [32m0[m bytes
 .../__pycache__/information_schema.cpython-312.pyc |    Bin [31m8928[m -> [32m0[m bytes
 .../mssql/__pycache__/json.cpython-312.pyc         |    Bin [31m5214[m -> [32m0[m bytes
 .../mssql/__pycache__/provision.cpython-312.pyc    |    Bin [31m7546[m -> [32m0[m bytes
 .../mssql/__pycache__/pymssql.cpython-312.pyc      |    Bin [31m5944[m -> [32m0[m bytes
 .../mssql/__pycache__/pyodbc.cpython-312.pyc       |    Bin [31m30622[m -> [32m0[m bytes
 .../sqlalchemy/dialects/mssql/aioodbc.py           |     63 [31m-[m
 .../sqlalchemy/dialects/mssql/base.py              |   4089 [31m-[m
 .../dialects/mssql/information_schema.py           |    285 [31m-[m
 .../sqlalchemy/dialects/mssql/json.py              |    129 [31m-[m
 .../sqlalchemy/dialects/mssql/provision.py         |    168 [31m-[m
 .../sqlalchemy/dialects/mssql/pymssql.py           |    126 [31m-[m
 .../sqlalchemy/dialects/mssql/pyodbc.py            |    760 [31m-[m
 .../sqlalchemy/dialects/mysql/__init__.py          |    104 [31m-[m
 .../mysql/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1981[m -> [32m0[m bytes
 .../mysql/__pycache__/aiomysql.cpython-312.pyc     |    Bin [31m11724[m -> [32m0[m bytes
 .../mysql/__pycache__/asyncmy.cpython-312.pyc      |    Bin [31m11187[m -> [32m0[m bytes
 .../mysql/__pycache__/base.cpython-312.pyc         |    Bin [31m154601[m -> [32m0[m bytes
 .../mysql/__pycache__/cymysql.cpython-312.pyc      |    Bin [31m4083[m -> [32m0[m bytes
 .../dialects/mysql/__pycache__/dml.cpython-312.pyc |    Bin [31m8343[m -> [32m0[m bytes
 .../mysql/__pycache__/enumerated.cpython-312.pyc   |    Bin [31m11526[m -> [32m0[m bytes
 .../mysql/__pycache__/expression.cpython-312.pyc   |    Bin [31m5215[m -> [32m0[m bytes
 .../mysql/__pycache__/json.cpython-312.pyc         |    Bin [31m3934[m -> [32m0[m bytes
 .../mysql/__pycache__/mariadb.cpython-312.pyc      |    Bin [31m2695[m -> [32m0[m bytes
 .../__pycache__/mariadbconnector.cpython-312.pyc   |    Bin [31m13777[m -> [32m0[m bytes
 .../__pycache__/mysqlconnector.cpython-312.pyc     |    Bin [31m14196[m -> [32m0[m bytes
 .../mysql/__pycache__/mysqldb.cpython-312.pyc      |    Bin [31m12364[m -> [32m0[m bytes
 .../mysql/__pycache__/provision.cpython-312.pyc    |    Bin [31m6363[m -> [32m0[m bytes
 .../mysql/__pycache__/pymysql.cpython-312.pyc      |    Bin [31m6205[m -> [32m0[m bytes
 .../mysql/__pycache__/pyodbc.cpython-312.pyc       |    Bin [31m6091[m -> [32m0[m bytes
 .../mysql/__pycache__/reflection.cpython-312.pyc   |    Bin [31m25848[m -> [32m0[m bytes
 .../__pycache__/reserved_words.cpython-312.pyc     |    Bin [31m4381[m -> [32m0[m bytes
 .../mysql/__pycache__/types.cpython-312.pyc        |    Bin [31m33045[m -> [32m0[m bytes
 .../sqlalchemy/dialects/mysql/aiomysql.py          |    250 [31m-[m
 .../sqlalchemy/dialects/mysql/asyncmy.py           |    231 [31m-[m
 .../sqlalchemy/dialects/mysql/base.py              |   3933 [31m-[m
 .../sqlalchemy/dialects/mysql/cymysql.py           |    106 [31m-[m
 .../site-packages/sqlalchemy/dialects/mysql/dml.py |    225 [31m-[m
 .../sqlalchemy/dialects/mysql/enumerated.py        |    282 [31m-[m
 .../sqlalchemy/dialects/mysql/expression.py        |    146 [31m-[m
 .../sqlalchemy/dialects/mysql/json.py              |     91 [31m-[m
 .../sqlalchemy/dialects/mysql/mariadb.py           |     73 [31m-[m
 .../sqlalchemy/dialects/mysql/mariadbconnector.py  |    322 [31m-[m
 .../sqlalchemy/dialects/mysql/mysqlconnector.py    |    302 [31m-[m
 .../sqlalchemy/dialects/mysql/mysqldb.py           |    314 [31m-[m
 .../sqlalchemy/dialects/mysql/provision.py         |    147 [31m-[m
 .../sqlalchemy/dialects/mysql/pymysql.py           |    158 [31m-[m
 .../sqlalchemy/dialects/mysql/pyodbc.py            |    157 [31m-[m
 .../sqlalchemy/dialects/mysql/reflection.py        |    727 [31m-[m
 .../sqlalchemy/dialects/mysql/reserved_words.py    |    570 [31m-[m
 .../sqlalchemy/dialects/mysql/types.py             |    835 [31m-[m
 .../sqlalchemy/dialects/oracle/__init__.py         |     81 [31m-[m
 .../oracle/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1653[m -> [32m0[m bytes
 .../oracle/__pycache__/base.cpython-312.pyc        |    Bin [31m153927[m -> [32m0[m bytes
 .../oracle/__pycache__/cx_oracle.cpython-312.pyc   |    Bin [31m60971[m -> [32m0[m bytes
 .../oracle/__pycache__/dictionary.cpython-312.pyc  |    Bin [31m24588[m -> [32m0[m bytes
 .../oracle/__pycache__/oracledb.cpython-312.pyc    |    Bin [31m41067[m -> [32m0[m bytes
 .../oracle/__pycache__/provision.cpython-312.pyc   |    Bin [31m13187[m -> [32m0[m bytes
 .../oracle/__pycache__/types.cpython-312.pyc       |    Bin [31m13202[m -> [32m0[m bytes
 .../oracle/__pycache__/vector.cpython-312.pyc      |    Bin [31m12214[m -> [32m0[m bytes
 .../sqlalchemy/dialects/oracle/base.py             |   3802 [31m-[m
 .../sqlalchemy/dialects/oracle/cx_oracle.py        |   1555 [31m-[m
 .../sqlalchemy/dialects/oracle/dictionary.py       |    507 [31m-[m
 .../sqlalchemy/dialects/oracle/oracledb.py         |    941 [31m-[m
 .../sqlalchemy/dialects/oracle/provision.py        |    297 [31m-[m
 .../sqlalchemy/dialects/oracle/types.py            |    316 [31m-[m
 .../sqlalchemy/dialects/oracle/vector.py           |    365 [31m-[m
 .../sqlalchemy/dialects/postgresql/__init__.py     |    167 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m3422[m -> [32m0[m bytes
 .../__pycache__/_psycopg_common.cpython-312.pyc    |    Bin [31m7915[m -> [32m0[m bytes
 .../postgresql/__pycache__/array.cpython-312.pyc   |    Bin [31m19557[m -> [32m0[m bytes
 .../postgresql/__pycache__/asyncpg.cpython-312.pyc |    Bin [31m58807[m -> [32m0[m bytes
 .../postgresql/__pycache__/base.cpython-312.pyc    |    Bin [31m216109[m -> [32m0[m bytes
 .../postgresql/__pycache__/dml.cpython-312.pyc     |    Bin [31m12586[m -> [32m0[m bytes
 .../postgresql/__pycache__/ext.cpython-312.pyc     |    Bin [31m20618[m -> [32m0[m bytes
 .../postgresql/__pycache__/hstore.cpython-312.pyc  |    Bin [31m15357[m -> [32m0[m bytes
 .../postgresql/__pycache__/json.cpython-312.pyc    |    Bin [31m16623[m -> [32m0[m bytes
 .../__pycache__/named_types.cpython-312.pyc        |    Bin [31m23023[m -> [32m0[m bytes
 .../__pycache__/operators.cpython-312.pyc          |    Bin [31m2145[m -> [32m0[m bytes
 .../postgresql/__pycache__/pg8000.cpython-312.pyc  |    Bin [31m30512[m -> [32m0[m bytes
 .../__pycache__/pg_catalog.cpython-312.pyc         |    Bin [31m11864[m -> [32m0[m bytes
 .../__pycache__/provision.cpython-312.pyc          |    Bin [31m7701[m -> [32m0[m bytes
 .../postgresql/__pycache__/psycopg.cpython-312.pyc |    Bin [31m40786[m -> [32m0[m bytes
 .../__pycache__/psycopg2.cpython-312.pyc           |    Bin [31m35961[m -> [32m0[m bytes
 .../__pycache__/psycopg2cffi.cpython-312.pyc       |    Bin [31m2152[m -> [32m0[m bytes
 .../postgresql/__pycache__/ranges.cpython-312.pyc  |    Bin [31m34757[m -> [32m0[m bytes
 .../postgresql/__pycache__/types.cpython-312.pyc   |    Bin [31m11505[m -> [32m0[m bytes
 .../dialects/postgresql/_psycopg_common.py         |    189 [31m-[m
 .../sqlalchemy/dialects/postgresql/array.py        |    519 [31m-[m
 .../sqlalchemy/dialects/postgresql/asyncpg.py      |   1284 [31m-[m
 .../sqlalchemy/dialects/postgresql/base.py         |   5328 [31m-[m
 .../sqlalchemy/dialects/postgresql/dml.py          |    339 [31m-[m
 .../sqlalchemy/dialects/postgresql/ext.py          |    540 [31m-[m
 .../sqlalchemy/dialects/postgresql/hstore.py       |    406 [31m-[m
 .../sqlalchemy/dialects/postgresql/json.py         |    395 [31m-[m
 .../sqlalchemy/dialects/postgresql/named_types.py  |    524 [31m-[m
 .../sqlalchemy/dialects/postgresql/operators.py    |    129 [31m-[m
 .../sqlalchemy/dialects/postgresql/pg8000.py       |    669 [31m-[m
 .../sqlalchemy/dialects/postgresql/pg_catalog.py   |    326 [31m-[m
 .../sqlalchemy/dialects/postgresql/provision.py    |    175 [31m-[m
 .../sqlalchemy/dialects/postgresql/psycopg.py      |    862 [31m-[m
 .../sqlalchemy/dialects/postgresql/psycopg2.py     |    892 [31m-[m
 .../sqlalchemy/dialects/postgresql/psycopg2cffi.py |     61 [31m-[m
 .../sqlalchemy/dialects/postgresql/ranges.py       |   1031 [31m-[m
 .../sqlalchemy/dialects/postgresql/types.py        |    313 [31m-[m
 .../sqlalchemy/dialects/sqlite/__init__.py         |     57 [31m-[m
 .../sqlite/__pycache__/__init__.cpython-312.pyc    |    Bin [31m1048[m -> [32m0[m bytes
 .../sqlite/__pycache__/aiosqlite.cpython-312.pyc   |    Bin [31m20197[m -> [32m0[m bytes
 .../sqlite/__pycache__/base.cpython-312.pyc        |    Bin [31m109064[m -> [32m0[m bytes
 .../sqlite/__pycache__/dml.cpython-312.pyc         |    Bin [31m10041[m -> [32m0[m bytes
 .../sqlite/__pycache__/json.cpython-312.pyc        |    Bin [31m3765[m -> [32m0[m bytes
 .../sqlite/__pycache__/provision.cpython-312.pyc   |    Bin [31m8720[m -> [32m0[m bytes
 .../sqlite/__pycache__/pysqlcipher.cpython-312.pyc |    Bin [31m6200[m -> [32m0[m bytes
 .../sqlite/__pycache__/pysqlite.cpython-312.pyc    |    Bin [31m31202[m -> [32m0[m bytes
 .../sqlalchemy/dialects/sqlite/aiosqlite.py        |    446 [31m-[m
 .../sqlalchemy/dialects/sqlite/base.py             |   3045 [31m-[m
 .../sqlalchemy/dialects/sqlite/dml.py              |    263 [31m-[m
 .../sqlalchemy/dialects/sqlite/json.py             |     92 [31m-[m
 .../sqlalchemy/dialects/sqlite/provision.py        |    223 [31m-[m
 .../sqlalchemy/dialects/sqlite/pysqlcipher.py      |    157 [31m-[m
 .../sqlalchemy/dialects/sqlite/pysqlite.py         |    756 [31m-[m
 .../dialects/type_migration_guidelines.txt         |    145 [31m-[m
 .../site-packages/sqlalchemy/engine/__init__.py    |     62 [31m-[m
 .../engine/__pycache__/__init__.cpython-312.pyc    |    Bin [31m2263[m -> [32m0[m bytes
 .../__pycache__/_py_processors.cpython-312.pyc     |    Bin [31m4486[m -> [32m0[m bytes
 .../engine/__pycache__/_py_row.cpython-312.pyc     |    Bin [31m5755[m -> [32m0[m bytes
 .../engine/__pycache__/_py_util.cpython-312.pyc    |    Bin [31m2194[m -> [32m0[m bytes
 .../engine/__pycache__/base.cpython-312.pyc        |    Bin [31m130222[m -> [32m0[m bytes
 .../__pycache__/characteristics.cpython-312.pyc    |    Bin [31m6830[m -> [32m0[m bytes
 .../engine/__pycache__/create.cpython-312.pyc      |    Bin [31m34944[m -> [32m0[m bytes
 .../engine/__pycache__/cursor.cpython-312.pyc      |    Bin [31m83062[m -> [32m0[m bytes
 .../engine/__pycache__/default.cpython-312.pyc     |    Bin [31m89190[m -> [32m0[m bytes
 .../engine/__pycache__/events.cpython-312.pyc      |    Bin [31m39909[m -> [32m0[m bytes
 .../engine/__pycache__/interfaces.cpython-312.pyc  |    Bin [31m102590[m -> [32m0[m bytes
 .../engine/__pycache__/mock.cpython-312.pyc        |    Bin [31m5660[m -> [32m0[m bytes
 .../engine/__pycache__/processors.cpython-312.pyc  |    Bin [31m1277[m -> [32m0[m bytes
 .../engine/__pycache__/reflection.cpython-312.pyc  |    Bin [31m80469[m -> [32m0[m bytes
 .../engine/__pycache__/result.cpython-312.pyc      |    Bin [31m91492[m -> [32m0[m bytes
 .../engine/__pycache__/row.cpython-312.pyc         |    Bin [31m17425[m -> [32m0[m bytes
 .../engine/__pycache__/strategies.cpython-312.pyc  |    Bin [31m541[m -> [32m0[m bytes
 .../engine/__pycache__/url.cpython-312.pyc         |    Bin [31m34391[m -> [32m0[m bytes
 .../engine/__pycache__/util.cpython-312.pyc        |    Bin [31m6622[m -> [32m0[m bytes
 .../sqlalchemy/engine/_py_processors.py            |    136 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/_py_row.py |    128 [31m-[m
 .../site-packages/sqlalchemy/engine/_py_util.py    |     74 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/base.py    |   3382 [31m-[m
 .../sqlalchemy/engine/characteristics.py           |    155 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/create.py  |    893 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/cursor.py  |   2298 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/default.py |   2394 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/events.py  |    965 [31m-[m
 .../site-packages/sqlalchemy/engine/interfaces.py  |   3471 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/mock.py    |    134 [31m-[m
 .../site-packages/sqlalchemy/engine/processors.py  |     61 [31m-[m
 .../site-packages/sqlalchemy/engine/reflection.py  |   2102 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/result.py  |   2387 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/row.py     |    400 [31m-[m
 .../site-packages/sqlalchemy/engine/strategies.py  |     16 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/url.py     |    924 [31m-[m
 .../Lib/site-packages/sqlalchemy/engine/util.py    |    167 [31m-[m
 .../Lib/site-packages/sqlalchemy/event/__init__.py |     26 [31m-[m
 .../event/__pycache__/__init__.cpython-312.pyc     |    Bin [31m872[m -> [32m0[m bytes
 .../event/__pycache__/api.cpython-312.pyc          |    Bin [31m9059[m -> [32m0[m bytes
 .../event/__pycache__/attr.cpython-312.pyc         |    Bin [31m31019[m -> [32m0[m bytes
 .../event/__pycache__/base.cpython-312.pyc         |    Bin [31m19948[m -> [32m0[m bytes
 .../event/__pycache__/legacy.cpython-312.pyc       |    Bin [31m9686[m -> [32m0[m bytes
 .../event/__pycache__/registry.cpython-312.pyc     |    Bin [31m12584[m -> [32m0[m bytes
 .../venv/Lib/site-packages/sqlalchemy/event/api.py |    220 [31m-[m
 .../Lib/site-packages/sqlalchemy/event/attr.py     |    676 [31m-[m
 .../Lib/site-packages/sqlalchemy/event/base.py     |    472 [31m-[m
 .../Lib/site-packages/sqlalchemy/event/legacy.py   |    258 [31m-[m
 .../Lib/site-packages/sqlalchemy/event/registry.py |    390 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/events.py    |     17 [31m-[m
 backend/venv/Lib/site-packages/sqlalchemy/exc.py   |    832 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/__init__.py   |     11 [31m-[m
 .../ext/__pycache__/__init__.cpython-312.pyc       |    Bin [31m339[m -> [32m0[m bytes
 .../__pycache__/associationproxy.cpython-312.pyc   |    Bin [31m87170[m -> [32m0[m bytes
 .../ext/__pycache__/automap.cpython-312.pyc        |    Bin [31m57387[m -> [32m0[m bytes
 .../ext/__pycache__/baked.cpython-312.pyc          |    Bin [31m23374[m -> [32m0[m bytes
 .../ext/__pycache__/compiler.cpython-312.pyc       |    Bin [31m21223[m -> [32m0[m bytes
 .../__pycache__/horizontal_shard.cpython-312.pyc   |    Bin [31m17634[m -> [32m0[m bytes
 .../ext/__pycache__/hybrid.cpython-312.pyc         |    Bin [31m59983[m -> [32m0[m bytes
 .../ext/__pycache__/indexable.cpython-312.pyc      |    Bin [31m13073[m -> [32m0[m bytes
 .../__pycache__/instrumentation.cpython-312.pyc    |    Bin [31m19855[m -> [32m0[m bytes
 .../ext/__pycache__/mutable.cpython-312.pyc        |    Bin [31m45821[m -> [32m0[m bytes
 .../ext/__pycache__/orderinglist.cpython-312.pyc   |    Bin [31m18066[m -> [32m0[m bytes
 .../ext/__pycache__/serializer.cpython-312.pyc     |    Bin [31m8034[m -> [32m0[m bytes
 .../sqlalchemy/ext/associationproxy.py             |   2027 [31m-[m
 .../sqlalchemy/ext/asyncio/__init__.py             |     25 [31m-[m
 .../asyncio/__pycache__/__init__.cpython-312.pyc   |    Bin [31m962[m -> [32m0[m bytes
 .../ext/asyncio/__pycache__/base.cpython-312.pyc   |    Bin [31m11340[m -> [32m0[m bytes
 .../ext/asyncio/__pycache__/engine.cpython-312.pyc |    Bin [31m57496[m -> [32m0[m bytes
 .../ext/asyncio/__pycache__/exc.cpython-312.pyc    |    Bin [31m1022[m -> [32m0[m bytes
 .../ext/asyncio/__pycache__/result.cpython-312.pyc |    Bin [31m37665[m -> [32m0[m bytes
 .../asyncio/__pycache__/scoping.cpython-312.pyc    |    Bin [31m56482[m -> [32m0[m bytes
 .../asyncio/__pycache__/session.cpython-312.pyc    |    Bin [31m71591[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/ext/asyncio/base.py   |    281 [31m-[m
 .../site-packages/sqlalchemy/ext/asyncio/engine.py |   1471 [31m-[m
 .../site-packages/sqlalchemy/ext/asyncio/exc.py    |     21 [31m-[m
 .../site-packages/sqlalchemy/ext/asyncio/result.py |    965 [31m-[m
 .../sqlalchemy/ext/asyncio/scoping.py              |   1599 [31m-[m
 .../sqlalchemy/ext/asyncio/session.py              |   1947 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/automap.py    |   1701 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/ext/baked.py |    570 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/compiler.py   |    600 [31m-[m
 .../sqlalchemy/ext/declarative/__init__.py         |     65 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1998[m -> [32m0[m bytes
 .../__pycache__/extensions.cpython-312.pyc         |    Bin [31m21221[m -> [32m0[m bytes
 .../sqlalchemy/ext/declarative/extensions.py       |    564 [31m-[m
 .../sqlalchemy/ext/horizontal_shard.py             |    478 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/hybrid.py     |   1535 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/indexable.py  |    364 [31m-[m
 .../sqlalchemy/ext/instrumentation.py              |    450 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/mutable.py    |   1085 [31m-[m
 .../site-packages/sqlalchemy/ext/mypy/__init__.py  |      6 [31m-[m
 .../ext/mypy/__pycache__/__init__.cpython-312.pyc  |    Bin [31m181[m -> [32m0[m bytes
 .../ext/mypy/__pycache__/apply.cpython-312.pyc     |    Bin [31m10499[m -> [32m0[m bytes
 .../mypy/__pycache__/decl_class.cpython-312.pyc    |    Bin [31m15805[m -> [32m0[m bytes
 .../ext/mypy/__pycache__/infer.cpython-312.pyc     |    Bin [31m15611[m -> [32m0[m bytes
 .../ext/mypy/__pycache__/names.cpython-312.pyc     |    Bin [31m11024[m -> [32m0[m bytes
 .../ext/mypy/__pycache__/plugin.cpython-312.pyc    |    Bin [31m12500[m -> [32m0[m bytes
 .../ext/mypy/__pycache__/util.cpython-312.pyc      |    Bin [31m13995[m -> [32m0[m bytes
 .../Lib/site-packages/sqlalchemy/ext/mypy/apply.py |    324 [31m-[m
 .../sqlalchemy/ext/mypy/decl_class.py              |    515 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/mypy/infer.py |    590 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/mypy/names.py |    335 [31m-[m
 .../site-packages/sqlalchemy/ext/mypy/plugin.py    |    303 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/mypy/util.py  |    357 [31m-[m
 .../site-packages/sqlalchemy/ext/orderinglist.py   |    439 [31m-[m
 .../Lib/site-packages/sqlalchemy/ext/serializer.py |    185 [31m-[m
 .../site-packages/sqlalchemy/future/__init__.py    |     16 [31m-[m
 .../future/__pycache__/__init__.cpython-312.pyc    |    Bin [31m449[m -> [32m0[m bytes
 .../future/__pycache__/engine.cpython-312.pyc      |    Bin [31m382[m -> [32m0[m bytes
 .../Lib/site-packages/sqlalchemy/future/engine.py  |     15 [31m-[m
 .../Lib/site-packages/sqlalchemy/inspection.py     |    174 [31m-[m
 backend/venv/Lib/site-packages/sqlalchemy/log.py   |    288 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/__init__.py   |    171 [31m-[m
 .../orm/__pycache__/__init__.cpython-312.pyc       |    Bin [31m6373[m -> [32m0[m bytes
 .../__pycache__/_orm_constructors.cpython-312.pyc  |    Bin [31m107027[m -> [32m0[m bytes
 .../orm/__pycache__/_typing.cpython-312.pyc        |    Bin [31m6799[m -> [32m0[m bytes
 .../orm/__pycache__/attributes.cpython-312.pyc     |    Bin [31m100588[m -> [32m0[m bytes
 .../orm/__pycache__/base.cpython-312.pyc           |    Bin [31m30332[m -> [32m0[m bytes
 .../__pycache__/bulk_persistence.cpython-312.pyc   |    Bin [31m64768[m -> [32m0[m bytes
 .../orm/__pycache__/clsregistry.cpython-312.pyc    |    Bin [31m23739[m -> [32m0[m bytes
 .../orm/__pycache__/collections.cpython-312.pyc    |    Bin [31m61751[m -> [32m0[m bytes
 .../orm/__pycache__/context.cpython-312.pyc        |    Bin [31m103133[m -> [32m0[m bytes
 .../orm/__pycache__/decl_api.cpython-312.pyc       |    Bin [31m69704[m -> [32m0[m bytes
 .../orm/__pycache__/decl_base.cpython-312.pyc      |    Bin [31m68889[m -> [32m0[m bytes
 .../orm/__pycache__/dependency.cpython-312.pyc     |    Bin [31m43102[m -> [32m0[m bytes
 .../__pycache__/descriptor_props.cpython-312.pyc   |    Bin [31m49622[m -> [32m0[m bytes
 .../orm/__pycache__/dynamic.cpython-312.pyc        |    Bin [31m12928[m -> [32m0[m bytes
 .../orm/__pycache__/evaluator.cpython-312.pyc      |    Bin [31m16734[m -> [32m0[m bytes
 .../orm/__pycache__/events.cpython-312.pyc         |    Bin [31m136473[m -> [32m0[m bytes
 .../sqlalchemy/orm/__pycache__/exc.cpython-312.pyc |    Bin [31m10204[m -> [32m0[m bytes
 .../orm/__pycache__/identity.cpython-312.pyc       |    Bin [31m12602[m -> [32m0[m bytes
 .../__pycache__/instrumentation.cpython-312.pyc    |    Bin [31m31185[m -> [32m0[m bytes
 .../orm/__pycache__/interfaces.cpython-312.pyc     |    Bin [31m54564[m -> [32m0[m bytes
 .../orm/__pycache__/loading.cpython-312.pyc        |    Bin [31m47051[m -> [32m0[m bytes
 .../__pycache__/mapped_collection.cpython-312.pyc  |    Bin [31m21873[m -> [32m0[m bytes
 .../orm/__pycache__/mapper.cpython-312.pyc         |    Bin [31m168895[m -> [32m0[m bytes
 .../orm/__pycache__/path_registry.cpython-312.pyc  |    Bin [31m31481[m -> [32m0[m bytes
 .../orm/__pycache__/persistence.cpython-312.pyc    |    Bin [31m48281[m -> [32m0[m bytes
 .../orm/__pycache__/properties.cpython-312.pyc     |    Bin [31m34639[m -> [32m0[m bytes
 .../orm/__pycache__/query.cpython-312.pyc          |    Bin [31m128756[m -> [32m0[m bytes
 .../orm/__pycache__/relationships.cpython-312.pyc  |    Bin [31m130380[m -> [32m0[m bytes
 .../orm/__pycache__/scoping.cpython-312.pyc        |    Bin [31m83096[m -> [32m0[m bytes
 .../orm/__pycache__/session.cpython-312.pyc        |    Bin [31m202705[m -> [32m0[m bytes
 .../orm/__pycache__/state.cpython-312.pyc          |    Bin [31m45855[m -> [32m0[m bytes
 .../orm/__pycache__/state_changes.cpython-312.pyc  |    Bin [31m7007[m -> [32m0[m bytes
 .../orm/__pycache__/strategies.cpython-312.pyc     |    Bin [31m105058[m -> [32m0[m bytes
 .../__pycache__/strategy_options.cpython-312.pyc   |    Bin [31m87501[m -> [32m0[m bytes
 .../orm/__pycache__/sync.cpython-312.pyc           |    Bin [31m6558[m -> [32m0[m bytes
 .../orm/__pycache__/unitofwork.cpython-312.pyc     |    Bin [31m34019[m -> [32m0[m bytes
 .../orm/__pycache__/util.cpython-312.pyc           |    Bin [31m85015[m -> [32m0[m bytes
 .../orm/__pycache__/writeonly.cpython-312.pyc      |    Bin [31m28765[m -> [32m0[m bytes
 .../sqlalchemy/orm/_orm_constructors.py            |   2661 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/_typing.py    |    179 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/attributes.py |   2845 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/base.py  |    971 [31m-[m
 .../sqlalchemy/orm/bulk_persistence.py             |   2135 [31m-[m
 .../site-packages/sqlalchemy/orm/clsregistry.py    |    571 [31m-[m
 .../site-packages/sqlalchemy/orm/collections.py    |   1627 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/context.py    |   3334 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/decl_api.py   |   2004 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/decl_base.py  |   2192 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/dependency.py |   1302 [31m-[m
 .../sqlalchemy/orm/descriptor_props.py             |   1092 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/dynamic.py    |    300 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/evaluator.py  |    379 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/events.py     |   3252 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/exc.py   |    237 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/identity.py   |    302 [31m-[m
 .../sqlalchemy/orm/instrumentation.py              |    754 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/interfaces.py |   1496 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/loading.py    |   1686 [31m-[m
 .../sqlalchemy/orm/mapped_collection.py            |    557 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/mapper.py     |   4444 [31m-[m
 .../site-packages/sqlalchemy/orm/path_registry.py  |    809 [31m-[m
 .../site-packages/sqlalchemy/orm/persistence.py    |   1788 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/properties.py |    935 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/query.py |   3459 [31m-[m
 .../site-packages/sqlalchemy/orm/relationships.py  |   3508 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/scoping.py    |   2148 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/session.py    |   5280 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/state.py |   1168 [31m-[m
 .../site-packages/sqlalchemy/orm/state_changes.py  |    196 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/strategies.py |   3470 [31m-[m
 .../sqlalchemy/orm/strategy_options.py             |   2568 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/sync.py  |    164 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/unitofwork.py |    796 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/orm/util.py  |   2403 [31m-[m
 .../Lib/site-packages/sqlalchemy/orm/writeonly.py  |    674 [31m-[m
 .../Lib/site-packages/sqlalchemy/pool/__init__.py  |     44 [31m-[m
 .../pool/__pycache__/__init__.cpython-312.pyc      |    Bin [31m1500[m -> [32m0[m bytes
 .../pool/__pycache__/base.cpython-312.pyc          |    Bin [31m56389[m -> [32m0[m bytes
 .../pool/__pycache__/events.cpython-312.pyc        |    Bin [31m14311[m -> [32m0[m bytes
 .../pool/__pycache__/impl.cpython-312.pyc          |    Bin [31m26274[m -> [32m0[m bytes
 .../venv/Lib/site-packages/sqlalchemy/pool/base.py |   1516 [31m-[m
 .../Lib/site-packages/sqlalchemy/pool/events.py    |    372 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/pool/impl.py |    588 [31m-[m
 backend/venv/Lib/site-packages/sqlalchemy/py.typed |      0
 .../venv/Lib/site-packages/sqlalchemy/schema.py    |     69 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/__init__.py   |    145 [31m-[m
 .../sql/__pycache__/__init__.cpython-312.pyc       |    Bin [31m4673[m -> [32m0[m bytes
 .../__pycache__/_dml_constructors.cpython-312.pyc  |    Bin [31m3981[m -> [32m0[m bytes
 .../_elements_constructors.cpython-312.pyc         |    Bin [31m66001[m -> [32m0[m bytes
 .../sql/__pycache__/_orm_types.cpython-312.pyc     |    Bin [31m613[m -> [32m0[m bytes
 .../sql/__pycache__/_py_util.cpython-312.pyc       |    Bin [31m2952[m -> [32m0[m bytes
 .../_selectable_constructors.cpython-312.pyc       |    Bin [31m25136[m -> [32m0[m bytes
 .../sql/__pycache__/_typing.cpython-312.pyc        |    Bin [31m15169[m -> [32m0[m bytes
 .../sql/__pycache__/annotation.cpython-312.pyc     |    Bin [31m21381[m -> [32m0[m bytes
 .../sql/__pycache__/base.cpython-312.pyc           |    Bin [31m100125[m -> [32m0[m bytes
 .../sql/__pycache__/cache_key.cpython-312.pyc      |    Bin [31m35628[m -> [32m0[m bytes
 .../sql/__pycache__/coercions.cpython-312.pyc      |    Bin [31m49046[m -> [32m0[m bytes
 .../sql/__pycache__/compiler.cpython-312.pyc       |    Bin [31m280214[m -> [32m0[m bytes
 .../sql/__pycache__/crud.cpython-312.pyc           |    Bin [31m48051[m -> [32m0[m bytes
 .../sqlalchemy/sql/__pycache__/ddl.cpython-312.pyc |    Bin [31m58520[m -> [32m0[m bytes
 .../__pycache__/default_comparator.cpython-312.pyc |    Bin [31m19466[m -> [32m0[m bytes
 .../sqlalchemy/sql/__pycache__/dml.cpython-312.pyc |    Bin [31m74303[m -> [32m0[m bytes
 .../sql/__pycache__/elements.cpython-312.pyc       |    Bin [31m214327[m -> [32m0[m bytes
 .../sql/__pycache__/events.cpython-312.pyc         |    Bin [31m19208[m -> [32m0[m bytes
 .../sql/__pycache__/expression.cpython-312.pyc     |    Bin [31m5133[m -> [32m0[m bytes
 .../sql/__pycache__/functions.cpython-312.pyc      |    Bin [31m78684[m -> [32m0[m bytes
 .../sql/__pycache__/lambdas.cpython-312.pyc        |    Bin [31m54770[m -> [32m0[m bytes
 .../sql/__pycache__/naming.cpython-312.pyc         |    Bin [31m8445[m -> [32m0[m bytes
 .../sql/__pycache__/operators.cpython-312.pyc      |    Bin [31m89878[m -> [32m0[m bytes
 .../sql/__pycache__/roles.cpython-312.pyc          |    Bin [31m12232[m -> [32m0[m bytes
 .../sql/__pycache__/schema.cpython-312.pyc         |    Bin [31m245949[m -> [32m0[m bytes
 .../sql/__pycache__/selectable.cpython-312.pyc     |    Bin [31m264571[m -> [32m0[m bytes
 .../sql/__pycache__/sqltypes.cpython-312.pyc       |    Bin [31m155290[m -> [32m0[m bytes
 .../sql/__pycache__/traversals.cpython-312.pyc     |    Bin [31m42335[m -> [32m0[m bytes
 .../sql/__pycache__/type_api.cpython-312.pyc       |    Bin [31m87804[m -> [32m0[m bytes
 .../sql/__pycache__/util.cpython-312.pyc           |    Bin [31m54375[m -> [32m0[m bytes
 .../sql/__pycache__/visitors.cpython-312.pyc       |    Bin [31m36053[m -> [32m0[m bytes
 .../sqlalchemy/sql/_dml_constructors.py            |    132 [31m-[m
 .../sqlalchemy/sql/_elements_constructors.py       |   1872 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/_orm_types.py |     20 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/_py_util.py   |     75 [31m-[m
 .../sqlalchemy/sql/_selectable_constructors.py     |    763 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/_typing.py    |    481 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/annotation.py |    587 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/sql/base.py  |   2219 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/cache_key.py  |   1057 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/coercions.py  |   1404 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/compiler.py   |   8034 [31m--[m
 .../venv/Lib/site-packages/sqlalchemy/sql/crud.py  |   1744 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/sql/ddl.py   |   1444 [31m-[m
 .../sqlalchemy/sql/default_comparator.py           |    551 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/sql/dml.py   |   1850 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/elements.py   |   5589 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/events.py     |    458 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/expression.py |    159 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/functions.py  |   2139 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/lambdas.py    |   1442 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/naming.py     |    209 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/operators.py  |   2623 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/sql/roles.py |    323 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/schema.py     |   6222 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/selectable.py |   7265 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/sqltypes.py   |   3930 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/traversals.py |   1024 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/type_api.py   |   2368 [31m-[m
 .../venv/Lib/site-packages/sqlalchemy/sql/util.py  |   1485 [31m-[m
 .../Lib/site-packages/sqlalchemy/sql/visitors.py   |   1164 [31m-[m
 .../site-packages/sqlalchemy/testing/__init__.py   |     96 [31m-[m
 .../testing/__pycache__/__init__.cpython-312.pyc   |    Bin [31m3317[m -> [32m0[m bytes
 .../testing/__pycache__/assertions.cpython-312.pyc |    Bin [31m42019[m -> [32m0[m bytes
 .../testing/__pycache__/assertsql.cpython-312.pyc  |    Bin [31m20262[m -> [32m0[m bytes
 .../testing/__pycache__/asyncio.cpython-312.pyc    |    Bin [31m4137[m -> [32m0[m bytes
 .../testing/__pycache__/config.cpython-312.pyc     |    Bin [31m18182[m -> [32m0[m bytes
 .../testing/__pycache__/engines.cpython-312.pyc    |    Bin [31m21172[m -> [32m0[m bytes
 .../testing/__pycache__/entities.cpython-312.pyc   |    Bin [31m4971[m -> [32m0[m bytes
 .../testing/__pycache__/exclusions.cpython-312.pyc |    Bin [31m23431[m -> [32m0[m bytes
 .../testing/__pycache__/pickleable.cpython-312.pyc |    Bin [31m6676[m -> [32m0[m bytes
 .../testing/__pycache__/profiling.cpython-312.pyc  |    Bin [31m13052[m -> [32m0[m bytes
 .../testing/__pycache__/provision.cpython-312.pyc  |    Bin [31m24967[m -> [32m0[m bytes
 .../__pycache__/requirements.cpython-312.pyc       |    Bin [31m92277[m -> [32m0[m bytes
 .../testing/__pycache__/schema.cpython-312.pyc     |    Bin [31m8358[m -> [32m0[m bytes
 .../testing/__pycache__/util.cpython-312.pyc       |    Bin [31m21761[m -> [32m0[m bytes
 .../testing/__pycache__/warnings.cpython-312.pyc   |    Bin [31m1991[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/testing/assertions.py |    994 [31m-[m
 .../site-packages/sqlalchemy/testing/assertsql.py  |    520 [31m-[m
 .../site-packages/sqlalchemy/testing/asyncio.py    |    135 [31m-[m
 .../Lib/site-packages/sqlalchemy/testing/config.py |    434 [31m-[m
 .../site-packages/sqlalchemy/testing/engines.py    |    478 [31m-[m
 .../site-packages/sqlalchemy/testing/entities.py   |    117 [31m-[m
 .../site-packages/sqlalchemy/testing/exclusions.py |    476 [31m-[m
 .../sqlalchemy/testing/fixtures/__init__.py        |     28 [31m-[m
 .../fixtures/__pycache__/__init__.cpython-312.pyc  |    Bin [31m898[m -> [32m0[m bytes
 .../fixtures/__pycache__/base.cpython-312.pyc      |    Bin [31m13453[m -> [32m0[m bytes
 .../fixtures/__pycache__/mypy.cpython-312.pyc      |    Bin [31m13659[m -> [32m0[m bytes
 .../fixtures/__pycache__/orm.cpython-312.pyc       |    Bin [31m11437[m -> [32m0[m bytes
 .../fixtures/__pycache__/sql.cpython-312.pyc       |    Bin [31m21385[m -> [32m0[m bytes
 .../sqlalchemy/testing/fixtures/base.py            |    366 [31m-[m
 .../sqlalchemy/testing/fixtures/mypy.py            |    332 [31m-[m
 .../sqlalchemy/testing/fixtures/orm.py             |    227 [31m-[m
 .../sqlalchemy/testing/fixtures/sql.py             |    482 [31m-[m
 .../site-packages/sqlalchemy/testing/pickleable.py |    155 [31m-[m
 .../sqlalchemy/testing/plugin/__init__.py          |      6 [31m-[m
 .../plugin/__pycache__/__init__.cpython-312.pyc    |    Bin [31m187[m -> [32m0[m bytes
 .../plugin/__pycache__/bootstrap.cpython-312.pyc   |    Bin [31m2138[m -> [32m0[m bytes
 .../plugin/__pycache__/plugin_base.cpython-312.pyc |    Bin [31m29217[m -> [32m0[m bytes
 .../__pycache__/pytestplugin.cpython-312.pyc       |    Bin [31m33601[m -> [32m0[m bytes
 .../sqlalchemy/testing/plugin/bootstrap.py         |     51 [31m-[m
 .../sqlalchemy/testing/plugin/plugin_base.py       |    828 [31m-[m
 .../sqlalchemy/testing/plugin/pytestplugin.py      |    892 [31m-[m
 .../site-packages/sqlalchemy/testing/profiling.py  |    327 [31m-[m
 .../site-packages/sqlalchemy/testing/provision.py  |    597 [31m-[m
 .../sqlalchemy/testing/requirements.py             |   1940 [31m-[m
 .../Lib/site-packages/sqlalchemy/testing/schema.py |    198 [31m-[m
 .../sqlalchemy/testing/suite/__init__.py           |     19 [31m-[m
 .../suite/__pycache__/__init__.cpython-312.pyc     |    Bin [31m554[m -> [32m0[m bytes
 .../suite/__pycache__/test_cte.cpython-312.pyc     |    Bin [31m11069[m -> [32m0[m bytes
 .../suite/__pycache__/test_ddl.cpython-312.pyc     |    Bin [31m18753[m -> [32m0[m bytes
 .../__pycache__/test_deprecations.cpython-312.pyc  |    Bin [31m8995[m -> [32m0[m bytes
 .../suite/__pycache__/test_dialect.cpython-312.pyc |    Bin [31m36179[m -> [32m0[m bytes
 .../suite/__pycache__/test_insert.cpython-312.pyc  |    Bin [31m25263[m -> [32m0[m bytes
 .../__pycache__/test_reflection.cpython-312.pyc    |    Bin [31m155398[m -> [32m0[m bytes
 .../suite/__pycache__/test_results.cpython-312.pyc |    Bin [31m25483[m -> [32m0[m bytes
 .../__pycache__/test_rowcount.cpython-312.pyc      |    Bin [31m10338[m -> [32m0[m bytes
 .../suite/__pycache__/test_select.cpython-312.pyc  |    Bin [31m115080[m -> [32m0[m bytes
 .../__pycache__/test_sequence.cpython-312.pyc      |    Bin [31m14988[m -> [32m0[m bytes
 .../suite/__pycache__/test_types.cpython-312.pyc   |    Bin [31m99057[m -> [32m0[m bytes
 .../__pycache__/test_unicode_ddl.cpython-312.pyc   |    Bin [31m7608[m -> [32m0[m bytes
 .../__pycache__/test_update_delete.cpython-312.pyc |    Bin [31m7387[m -> [32m0[m bytes
 .../sqlalchemy/testing/suite/test_cte.py           |    237 [31m-[m
 .../sqlalchemy/testing/suite/test_ddl.py           |    389 [31m-[m
 .../sqlalchemy/testing/suite/test_deprecations.py  |    153 [31m-[m
 .../sqlalchemy/testing/suite/test_dialect.py       |    776 [31m-[m
 .../sqlalchemy/testing/suite/test_insert.py        |    630 [31m-[m
 .../sqlalchemy/testing/suite/test_reflection.py    |   3557 [31m-[m
 .../sqlalchemy/testing/suite/test_results.py       |    504 [31m-[m
 .../sqlalchemy/testing/suite/test_rowcount.py      |    258 [31m-[m
 .../sqlalchemy/testing/suite/test_select.py        |   2010 [31m-[m
 .../sqlalchemy/testing/suite/test_sequence.py      |    317 [31m-[m
 .../sqlalchemy/testing/suite/test_types.py         |   2147 [31m-[m
 .../sqlalchemy/testing/suite/test_unicode_ddl.py   |    189 [31m-[m
 .../sqlalchemy/testing/suite/test_update_delete.py |    139 [31m-[m
 .../Lib/site-packages/sqlalchemy/testing/util.py   |    535 [31m-[m
 .../site-packages/sqlalchemy/testing/warnings.py   |     52 [31m-[m
 backend/venv/Lib/site-packages/sqlalchemy/types.py |     74 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/__init__.py  |    162 [31m-[m
 .../util/__pycache__/__init__.cpython-312.pyc      |    Bin [31m5726[m -> [32m0[m bytes
 .../util/__pycache__/_collections.cpython-312.pyc  |    Bin [31m31774[m -> [32m0[m bytes
 .../__pycache__/_concurrency_py3k.cpython-312.pyc  |    Bin [31m10833[m -> [32m0[m bytes
 .../util/__pycache__/_has_cy.cpython-312.pyc       |    Bin [31m1078[m -> [32m0[m bytes
 .../__pycache__/_py_collections.cpython-312.pyc    |    Bin [31m29221[m -> [32m0[m bytes
 .../util/__pycache__/compat.cpython-312.pyc        |    Bin [31m12926[m -> [32m0[m bytes
 .../util/__pycache__/concurrency.cpython-312.pyc   |    Bin [31m4082[m -> [32m0[m bytes
 .../util/__pycache__/deprecations.cpython-312.pyc  |    Bin [31m13631[m -> [32m0[m bytes
 .../util/__pycache__/langhelpers.cpython-312.pyc   |    Bin [31m86709[m -> [32m0[m bytes
 .../util/__pycache__/preloaded.cpython-312.pyc     |    Bin [31m5870[m -> [32m0[m bytes
 .../util/__pycache__/queue.cpython-312.pyc         |    Bin [31m14558[m -> [32m0[m bytes
 .../util/__pycache__/tool_support.cpython-312.pyc  |    Bin [31m8683[m -> [32m0[m bytes
 .../util/__pycache__/topological.cpython-312.pyc   |    Bin [31m3894[m -> [32m0[m bytes
 .../util/__pycache__/typing.cpython-312.pyc        |    Bin [31m26147[m -> [32m0[m bytes
 .../site-packages/sqlalchemy/util/_collections.py  |    717 [31m-[m
 .../sqlalchemy/util/_concurrency_py3k.py           |    288 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/_has_cy.py   |     40 [31m-[m
 .../sqlalchemy/util/_py_collections.py             |    541 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/compat.py    |    316 [31m-[m
 .../site-packages/sqlalchemy/util/concurrency.py   |    110 [31m-[m
 .../site-packages/sqlalchemy/util/deprecations.py  |    401 [31m-[m
 .../site-packages/sqlalchemy/util/langhelpers.py   |   2306 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/preloaded.py |    150 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/queue.py     |    322 [31m-[m
 .../site-packages/sqlalchemy/util/tool_support.py  |    201 [31m-[m
 .../site-packages/sqlalchemy/util/topological.py   |    120 [31m-[m
 .../Lib/site-packages/sqlalchemy/util/typing.py    |    734 [31m-[m
 .../starlette-0.50.0.dist-info/INSTALLER           |      1 [31m-[m
 .../starlette-0.50.0.dist-info/METADATA            |    177 [31m-[m
 .../starlette-0.50.0.dist-info/RECORD              |     74 [31m-[m
 .../site-packages/starlette-0.50.0.dist-info/WHEEL |      4 [31m-[m
 .../starlette-0.50.0.dist-info/licenses/LICENSE.md |     27 [31m-[m
 .../venv/Lib/site-packages/starlette/__init__.py   |      1 [31m-[m
 .../starlette/__pycache__/__init__.cpython-312.pyc |    Bin [31m198[m -> [32m0[m bytes
 .../__pycache__/_exception_handler.cpython-312.pyc |    Bin [31m3057[m -> [32m0[m bytes
 .../starlette/__pycache__/_utils.cpython-312.pyc   |    Bin [31m5104[m -> [32m0[m bytes
 .../__pycache__/applications.cpython-312.pyc       |    Bin [31m12868[m -> [32m0[m bytes
 .../__pycache__/authentication.cpython-312.pyc     |    Bin [31m7699[m -> [32m0[m bytes
 .../__pycache__/background.cpython-312.pyc         |    Bin [31m2519[m -> [32m0[m bytes
 .../__pycache__/concurrency.cpython-312.pyc        |    Bin [31m3159[m -> [32m0[m bytes
 .../starlette/__pycache__/config.cpython-312.pyc   |    Bin [31m7497[m -> [32m0[m bytes
 .../__pycache__/convertors.cpython-312.pyc         |    Bin [31m4750[m -> [32m0[m bytes
 .../__pycache__/datastructures.cpython-312.pyc     |    Bin [31m39484[m -> [32m0[m bytes
 .../__pycache__/endpoints.cpython-312.pyc          |    Bin [31m7939[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m2382[m -> [32m0[m bytes
 .../__pycache__/formparsers.cpython-312.pyc        |    Bin [31m14254[m -> [32m0[m bytes
 .../starlette/__pycache__/requests.cpython-312.pyc |    Bin [31m16323[m -> [32m0[m bytes
 .../__pycache__/responses.cpython-312.pyc          |    Bin [31m30215[m -> [32m0[m bytes
 .../starlette/__pycache__/routing.cpython-312.pyc  |    Bin [31m43909[m -> [32m0[m bytes
 .../starlette/__pycache__/schemas.cpython-312.pyc  |    Bin [31m7049[m -> [32m0[m bytes
 .../__pycache__/staticfiles.cpython-312.pyc        |    Bin [31m11525[m -> [32m0[m bytes
 .../starlette/__pycache__/status.cpython-312.pyc   |    Bin [31m5168[m -> [32m0[m bytes
 .../__pycache__/templating.cpython-312.pyc         |    Bin [31m9970[m -> [32m0[m bytes
 .../__pycache__/testclient.cpython-312.pyc         |    Bin [31m33119[m -> [32m0[m bytes
 .../starlette/__pycache__/types.cpython-312.pyc    |    Bin [31m1303[m -> [32m0[m bytes
 .../__pycache__/websockets.cpython-312.pyc         |    Bin [31m11807[m -> [32m0[m bytes
 .../site-packages/starlette/_exception_handler.py  |     65 [31m-[m
 backend/venv/Lib/site-packages/starlette/_utils.py |    103 [31m-[m
 .../Lib/site-packages/starlette/applications.py    |    244 [31m-[m
 .../Lib/site-packages/starlette/authentication.py  |    142 [31m-[m
 .../venv/Lib/site-packages/starlette/background.py |     36 [31m-[m
 .../Lib/site-packages/starlette/concurrency.py     |     57 [31m-[m
 backend/venv/Lib/site-packages/starlette/config.py |    140 [31m-[m
 .../venv/Lib/site-packages/starlette/convertors.py |     89 [31m-[m
 .../Lib/site-packages/starlette/datastructures.py  |    691 [31m-[m
 .../venv/Lib/site-packages/starlette/endpoints.py  |    123 [31m-[m
 .../venv/Lib/site-packages/starlette/exceptions.py |     33 [31m-[m
 .../Lib/site-packages/starlette/formparsers.py     |    276 [31m-[m
 .../site-packages/starlette/middleware/__init__.py |     37 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m2522[m -> [32m0[m bytes
 .../__pycache__/authentication.cpython-312.pyc     |    Bin [31m2882[m -> [32m0[m bytes
 .../middleware/__pycache__/base.cpython-312.pyc    |    Bin [31m11785[m -> [32m0[m bytes
 .../middleware/__pycache__/cors.cpython-312.pyc    |    Bin [31m7443[m -> [32m0[m bytes
 .../middleware/__pycache__/errors.cpython-312.pyc  |    Bin [31m9922[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m4088[m -> [32m0[m bytes
 .../middleware/__pycache__/gzip.cpython-312.pyc    |    Bin [31m8777[m -> [32m0[m bytes
 .../__pycache__/httpsredirect.cpython-312.pyc      |    Bin [31m1757[m -> [32m0[m bytes
 .../__pycache__/sessions.cpython-312.pyc           |    Bin [31m4650[m -> [32m0[m bytes
 .../__pycache__/trustedhost.cpython-312.pyc        |    Bin [31m3123[m -> [32m0[m bytes
 .../middleware/__pycache__/wsgi.cpython-312.pyc    |    Bin [31m8521[m -> [32m0[m bytes
 .../starlette/middleware/authentication.py         |     52 [31m-[m
 .../Lib/site-packages/starlette/middleware/base.py |    244 [31m-[m
 .../Lib/site-packages/starlette/middleware/cors.py |    172 [31m-[m
 .../site-packages/starlette/middleware/errors.py   |    259 [31m-[m
 .../starlette/middleware/exceptions.py             |     73 [31m-[m
 .../Lib/site-packages/starlette/middleware/gzip.py |    145 [31m-[m
 .../starlette/middleware/httpsredirect.py          |     19 [31m-[m
 .../site-packages/starlette/middleware/sessions.py |     85 [31m-[m
 .../starlette/middleware/trustedhost.py            |     60 [31m-[m
 .../Lib/site-packages/starlette/middleware/wsgi.py |    153 [31m-[m
 backend/venv/Lib/site-packages/starlette/py.typed  |      0
 .../venv/Lib/site-packages/starlette/requests.py   |    324 [31m-[m
 .../venv/Lib/site-packages/starlette/responses.py  |    566 [31m-[m
 .../venv/Lib/site-packages/starlette/routing.py    |    876 [31m-[m
 .../venv/Lib/site-packages/starlette/schemas.py    |    148 [31m-[m
 .../Lib/site-packages/starlette/staticfiles.py     |    217 [31m-[m
 backend/venv/Lib/site-packages/starlette/status.py |    209 [31m-[m
 .../venv/Lib/site-packages/starlette/templating.py |    217 [31m-[m
 .../venv/Lib/site-packages/starlette/testclient.py |    739 [31m-[m
 backend/venv/Lib/site-packages/starlette/types.py  |     26 [31m-[m
 .../venv/Lib/site-packages/starlette/websockets.py |    196 [31m-[m
 .../site-packages/tqdm-4.67.1.dist-info/INSTALLER  |      1 [31m-[m
 .../site-packages/tqdm-4.67.1.dist-info/LICENCE    |     49 [31m-[m
 .../site-packages/tqdm-4.67.1.dist-info/METADATA   |   1594 [31m-[m
 .../Lib/site-packages/tqdm-4.67.1.dist-info/RECORD |     74 [31m-[m
 .../Lib/site-packages/tqdm-4.67.1.dist-info/WHEEL  |      5 [31m-[m
 .../tqdm-4.67.1.dist-info/entry_points.txt         |      2 [31m-[m
 .../tqdm-4.67.1.dist-info/top_level.txt            |      1 [31m-[m
 backend/venv/Lib/site-packages/tqdm/__init__.py    |     38 [31m-[m
 backend/venv/Lib/site-packages/tqdm/__main__.py    |      3 [31m-[m
 .../tqdm/__pycache__/__init__.cpython-312.pyc      |    Bin [31m1666[m -> [32m0[m bytes
 .../tqdm/__pycache__/__main__.cpython-312.pyc      |    Bin [31m220[m -> [32m0[m bytes
 .../tqdm/__pycache__/_dist_ver.cpython-312.pyc     |    Bin [31m194[m -> [32m0[m bytes
 .../tqdm/__pycache__/_main.cpython-312.pyc         |    Bin [31m468[m -> [32m0[m bytes
 .../tqdm/__pycache__/_monitor.cpython-312.pyc      |    Bin [31m4149[m -> [32m0[m bytes
 .../tqdm/__pycache__/_tqdm.cpython-312.pyc         |    Bin [31m463[m -> [32m0[m bytes
 .../tqdm/__pycache__/_tqdm_gui.cpython-312.pyc     |    Bin [31m476[m -> [32m0[m bytes
 .../__pycache__/_tqdm_notebook.cpython-312.pyc     |    Bin [31m497[m -> [32m0[m bytes
 .../tqdm/__pycache__/_tqdm_pandas.cpython-312.pyc  |    Bin [31m1401[m -> [32m0[m bytes
 .../tqdm/__pycache__/_utils.cpython-312.pyc        |    Bin [31m875[m -> [32m0[m bytes
 .../tqdm/__pycache__/asyncio.cpython-312.pyc       |    Bin [31m4455[m -> [32m0[m bytes
 .../tqdm/__pycache__/auto.cpython-312.pyc          |    Bin [31m1329[m -> [32m0[m bytes
 .../tqdm/__pycache__/autonotebook.cpython-312.pyc  |    Bin [31m1240[m -> [32m0[m bytes
 .../tqdm/__pycache__/cli.cpython-312.pyc           |    Bin [31m15410[m -> [32m0[m bytes
 .../tqdm/__pycache__/dask.cpython-312.pyc          |    Bin [31m2538[m -> [32m0[m bytes
 .../tqdm/__pycache__/gui.cpython-312.pyc           |    Bin [31m7776[m -> [32m0[m bytes
 .../tqdm/__pycache__/keras.cpython-312.pyc         |    Bin [31m6890[m -> [32m0[m bytes
 .../tqdm/__pycache__/notebook.cpython-312.pyc      |    Bin [31m11622[m -> [32m0[m bytes
 .../tqdm/__pycache__/rich.cpython-312.pyc          |    Bin [31m7214[m -> [32m0[m bytes
 .../tqdm/__pycache__/std.cpython-312.pyc           |    Bin [31m64461[m -> [32m0[m bytes
 .../tqdm/__pycache__/tk.cpython-312.pyc            |    Bin [31m9919[m -> [32m0[m bytes
 .../tqdm/__pycache__/utils.cpython-312.pyc         |    Bin [31m18772[m -> [32m0[m bytes
 .../tqdm/__pycache__/version.cpython-312.pyc       |    Bin [31m593[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/tqdm/_dist_ver.py   |      1 [31m-[m
 backend/venv/Lib/site-packages/tqdm/_main.py       |      9 [31m-[m
 backend/venv/Lib/site-packages/tqdm/_monitor.py    |     95 [31m-[m
 backend/venv/Lib/site-packages/tqdm/_tqdm.py       |      9 [31m-[m
 backend/venv/Lib/site-packages/tqdm/_tqdm_gui.py   |      9 [31m-[m
 .../venv/Lib/site-packages/tqdm/_tqdm_notebook.py  |      9 [31m-[m
 .../venv/Lib/site-packages/tqdm/_tqdm_pandas.py    |     24 [31m-[m
 backend/venv/Lib/site-packages/tqdm/_utils.py      |     11 [31m-[m
 backend/venv/Lib/site-packages/tqdm/asyncio.py     |     93 [31m-[m
 backend/venv/Lib/site-packages/tqdm/auto.py        |     40 [31m-[m
 .../venv/Lib/site-packages/tqdm/autonotebook.py    |     29 [31m-[m
 backend/venv/Lib/site-packages/tqdm/cli.py         |    324 [31m-[m
 backend/venv/Lib/site-packages/tqdm/completion.sh  |     19 [31m-[m
 .../Lib/site-packages/tqdm/contrib/__init__.py     |     92 [31m-[m
 .../contrib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m4179[m -> [32m0[m bytes
 .../tqdm/contrib/__pycache__/bells.cpython-312.pyc |    Bin [31m1300[m -> [32m0[m bytes
 .../contrib/__pycache__/concurrent.cpython-312.pyc |    Bin [31m4651[m -> [32m0[m bytes
 .../contrib/__pycache__/discord.cpython-312.pyc    |    Bin [31m8070[m -> [32m0[m bytes
 .../contrib/__pycache__/itertools.cpython-312.pyc  |    Bin [31m1414[m -> [32m0[m bytes
 .../contrib/__pycache__/logging.cpython-312.pyc    |    Bin [31m5122[m -> [32m0[m bytes
 .../tqdm/contrib/__pycache__/slack.cpython-312.pyc |    Bin [31m6079[m -> [32m0[m bytes
 .../contrib/__pycache__/telegram.cpython-312.pyc   |    Bin [31m7717[m -> [32m0[m bytes
 .../__pycache__/utils_worker.cpython-312.pyc       |    Bin [31m2068[m -> [32m0[m bytes
 .../venv/Lib/site-packages/tqdm/contrib/bells.py   |     26 [31m-[m
 .../Lib/site-packages/tqdm/contrib/concurrent.py   |    105 [31m-[m
 .../venv/Lib/site-packages/tqdm/contrib/discord.py |    156 [31m-[m
 .../Lib/site-packages/tqdm/contrib/itertools.py    |     35 [31m-[m
 .../venv/Lib/site-packages/tqdm/contrib/logging.py |    126 [31m-[m
 .../venv/Lib/site-packages/tqdm/contrib/slack.py   |    120 [31m-[m
 .../Lib/site-packages/tqdm/contrib/telegram.py     |    153 [31m-[m
 .../Lib/site-packages/tqdm/contrib/utils_worker.py |     38 [31m-[m
 backend/venv/Lib/site-packages/tqdm/dask.py        |     44 [31m-[m
 backend/venv/Lib/site-packages/tqdm/gui.py         |    179 [31m-[m
 backend/venv/Lib/site-packages/tqdm/keras.py       |    122 [31m-[m
 backend/venv/Lib/site-packages/tqdm/notebook.py    |    317 [31m-[m
 backend/venv/Lib/site-packages/tqdm/rich.py        |    151 [31m-[m
 backend/venv/Lib/site-packages/tqdm/std.py         |   1524 [31m-[m
 backend/venv/Lib/site-packages/tqdm/tk.py          |    196 [31m-[m
 backend/venv/Lib/site-packages/tqdm/tqdm.1         |    314 [31m-[m
 backend/venv/Lib/site-packages/tqdm/utils.py       |    399 [31m-[m
 backend/venv/Lib/site-packages/tqdm/version.py     |      9 [31m-[m
 backend/venv/Lib/site-packages/typer/__init__.py   |     39 [31m-[m
 backend/venv/Lib/site-packages/typer/__main__.py   |      3 [31m-[m
 .../typer/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1446[m -> [32m0[m bytes
 .../typer/__pycache__/__main__.cpython-312.pyc     |    Bin [31m221[m -> [32m0[m bytes
 .../_completion_classes.cpython-312.pyc            |    Bin [31m10468[m -> [32m0[m bytes
 .../__pycache__/_completion_shared.cpython-312.pyc |    Bin [31m10301[m -> [32m0[m bytes
 .../typer/__pycache__/_types.cpython-312.pyc       |    Bin [31m1245[m -> [32m0[m bytes
 .../typer/__pycache__/_typing.cpython-312.pyc      |    Bin [31m2840[m -> [32m0[m bytes
 .../typer/__pycache__/cli.cpython-312.pyc          |    Bin [31m14179[m -> [32m0[m bytes
 .../typer/__pycache__/colors.cpython-312.pyc       |    Bin [31m661[m -> [32m0[m bytes
 .../typer/__pycache__/completion.cpython-312.pyc   |    Bin [31m5337[m -> [32m0[m bytes
 .../typer/__pycache__/core.cpython-312.pyc         |    Bin [31m31037[m -> [32m0[m bytes
 .../typer/__pycache__/main.cpython-312.pyc         |    Bin [31m44440[m -> [32m0[m bytes
 .../typer/__pycache__/models.cpython-312.pyc       |    Bin [31m18831[m -> [32m0[m bytes
 .../typer/__pycache__/params.cpython-312.pyc       |    Bin [31m14433[m -> [32m0[m bytes
 .../typer/__pycache__/rich_utils.cpython-312.pyc   |    Bin [31m26449[m -> [32m0[m bytes
 .../typer/__pycache__/testing.cpython-312.pyc      |    Bin [31m1449[m -> [32m0[m bytes
 .../typer/__pycache__/utils.cpython-312.pyc        |    Bin [31m7326[m -> [32m0[m bytes
 .../Lib/site-packages/typer/_completion_classes.py |    206 [31m-[m
 .../Lib/site-packages/typer/_completion_shared.py  |    259 [31m-[m
 backend/venv/Lib/site-packages/typer/_types.py     |     27 [31m-[m
 backend/venv/Lib/site-packages/typer/_typing.py    |     83 [31m-[m
 backend/venv/Lib/site-packages/typer/cli.py        |    308 [31m-[m
 backend/venv/Lib/site-packages/typer/colors.py     |     20 [31m-[m
 backend/venv/Lib/site-packages/typer/completion.py |    147 [31m-[m
 backend/venv/Lib/site-packages/typer/core.py       |    829 [31m-[m
 backend/venv/Lib/site-packages/typer/main.py       |   1157 [31m-[m
 backend/venv/Lib/site-packages/typer/models.py     |    541 [31m-[m
 backend/venv/Lib/site-packages/typer/params.py     |    479 [31m-[m
 backend/venv/Lib/site-packages/typer/py.typed      |      0
 backend/venv/Lib/site-packages/typer/rich_utils.py |    752 [31m-[m
 backend/venv/Lib/site-packages/typer/testing.py    |     30 [31m-[m
 backend/venv/Lib/site-packages/typer/utils.py      |    190 [31m-[m
 .../typer_slim-0.21.0.dist-info/INSTALLER          |      1 [31m-[m
 .../typer_slim-0.21.0.dist-info/METADATA           |    425 [31m-[m
 .../typer_slim-0.21.0.dist-info/RECORD             |     39 [31m-[m
 .../typer_slim-0.21.0.dist-info/WHEEL              |      4 [31m-[m
 .../typer_slim-0.21.0.dist-info/entry_points.txt   |      4 [31m-[m
 .../typer_slim-0.21.0.dist-info/licenses/LICENSE   |     21 [31m-[m
 .../typing_extensions-4.15.0.dist-info/INSTALLER   |      1 [31m-[m
 .../typing_extensions-4.15.0.dist-info/METADATA    |     72 [31m-[m
 .../typing_extensions-4.15.0.dist-info/RECORD      |      7 [31m-[m
 .../typing_extensions-4.15.0.dist-info/WHEEL       |      4 [31m-[m
 .../licenses/LICENSE                               |    279 [31m-[m
 .../venv/Lib/site-packages/typing_extensions.py    |   4317 [31m-[m
 .../typing_inspection-0.4.2.dist-info/INSTALLER    |      1 [31m-[m
 .../typing_inspection-0.4.2.dist-info/METADATA     |     49 [31m-[m
 .../typing_inspection-0.4.2.dist-info/RECORD       |     13 [31m-[m
 .../typing_inspection-0.4.2.dist-info/WHEEL        |      4 [31m-[m
 .../licenses/LICENSE                               |     21 [31m-[m
 .../site-packages/typing_inspection/__init__.py    |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m179[m -> [32m0[m bytes
 .../__pycache__/introspection.cpython-312.pyc      |    Bin [31m17776[m -> [32m0[m bytes
 .../__pycache__/typing_objects.cpython-312.pyc     |    Bin [31m17355[m -> [32m0[m bytes
 .../typing_inspection/introspection.py             |    587 [31m-[m
 .../Lib/site-packages/typing_inspection/py.typed   |      0
 .../typing_inspection/typing_objects.py            |    607 [31m-[m
 .../typing_inspection/typing_objects.pyi           |    417 [31m-[m
 .../uritemplate-4.2.0.dist-info/INSTALLER          |      1 [31m-[m
 .../uritemplate-4.2.0.dist-info/METADATA           |     84 [31m-[m
 .../uritemplate-4.2.0.dist-info/RECORD             |     17 [31m-[m
 .../uritemplate-4.2.0.dist-info/WHEEL              |      5 [31m-[m
 .../uritemplate-4.2.0.dist-info/licenses/LICENSE   |      3 [31m-[m
 .../uritemplate-4.2.0.dist-info/top_level.txt      |      1 [31m-[m
 .../venv/Lib/site-packages/uritemplate/__init__.py |     33 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m1345[m -> [32m0[m bytes
 .../uritemplate/__pycache__/api.cpython-312.pyc    |    Bin [31m3002[m -> [32m0[m bytes
 .../__pycache__/orderedset.cpython-312.pyc         |    Bin [31m4939[m -> [32m0[m bytes
 .../__pycache__/template.cpython-312.pyc           |    Bin [31m6931[m -> [32m0[m bytes
 .../__pycache__/variable.cpython-312.pyc           |    Bin [31m23459[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/uritemplate/api.py  |     86 [31m-[m
 .../Lib/site-packages/uritemplate/orderedset.py    |     92 [31m-[m
 .../venv/Lib/site-packages/uritemplate/py.typed    |      0
 .../venv/Lib/site-packages/uritemplate/template.py |    169 [31m-[m
 .../venv/Lib/site-packages/uritemplate/variable.py |    564 [31m-[m
 .../urllib3-2.6.2.dist-info/INSTALLER              |      1 [31m-[m
 .../site-packages/urllib3-2.6.2.dist-info/METADATA |    156 [31m-[m
 .../site-packages/urllib3-2.6.2.dist-info/RECORD   |     79 [31m-[m
 .../site-packages/urllib3-2.6.2.dist-info/WHEEL    |      4 [31m-[m
 .../urllib3-2.6.2.dist-info/licenses/LICENSE.txt   |     21 [31m-[m
 backend/venv/Lib/site-packages/urllib3/__init__.py |    211 [31m-[m
 .../urllib3/__pycache__/__init__.cpython-312.pyc   |    Bin [31m7294[m -> [32m0[m bytes
 .../__pycache__/_base_connection.cpython-312.pyc   |    Bin [31m6844[m -> [32m0[m bytes
 .../__pycache__/_collections.cpython-312.pyc       |    Bin [31m22875[m -> [32m0[m bytes
 .../__pycache__/_request_methods.cpython-312.pyc   |    Bin [31m10586[m -> [32m0[m bytes
 .../urllib3/__pycache__/_version.cpython-312.pyc   |    Bin [31m777[m -> [32m0[m bytes
 .../urllib3/__pycache__/connection.cpython-312.pyc |    Bin [31m38885[m -> [32m0[m bytes
 .../__pycache__/connectionpool.cpython-312.pyc     |    Bin [31m39714[m -> [32m0[m bytes
 .../urllib3/__pycache__/exceptions.cpython-312.pyc |    Bin [31m16595[m -> [32m0[m bytes
 .../urllib3/__pycache__/fields.cpython-312.pyc     |    Bin [31m11988[m -> [32m0[m bytes
 .../urllib3/__pycache__/filepost.cpython-312.pyc   |    Bin [31m3463[m -> [32m0[m bytes
 .../__pycache__/poolmanager.cpython-312.pyc        |    Bin [31m24279[m -> [32m0[m bytes
 .../urllib3/__pycache__/response.cpython-312.pyc   |    Bin [31m57399[m -> [32m0[m bytes
 .../Lib/site-packages/urllib3/_base_connection.py  |    165 [31m-[m
 .../venv/Lib/site-packages/urllib3/_collections.py |    487 [31m-[m
 .../Lib/site-packages/urllib3/_request_methods.py  |    278 [31m-[m
 backend/venv/Lib/site-packages/urllib3/_version.py |     34 [31m-[m
 .../venv/Lib/site-packages/urllib3/connection.py   |   1099 [31m-[m
 .../Lib/site-packages/urllib3/connectionpool.py    |   1178 [31m-[m
 .../Lib/site-packages/urllib3/contrib/__init__.py  |      0
 .../contrib/__pycache__/__init__.cpython-312.pyc   |    Bin [31m177[m -> [32m0[m bytes
 .../contrib/__pycache__/pyopenssl.cpython-312.pyc  |    Bin [31m28201[m -> [32m0[m bytes
 .../contrib/__pycache__/socks.cpython-312.pyc      |    Bin [31m8155[m -> [32m0[m bytes
 .../urllib3/contrib/emscripten/__init__.py         |     16 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m885[m -> [32m0[m bytes
 .../__pycache__/connection.cpython-312.pyc         |    Bin [31m10291[m -> [32m0[m bytes
 .../emscripten/__pycache__/fetch.cpython-312.pyc   |    Bin [31m28623[m -> [32m0[m bytes
 .../emscripten/__pycache__/request.cpython-312.pyc |    Bin [31m1405[m -> [32m0[m bytes
 .../__pycache__/response.cpython-312.pyc           |    Bin [31m12193[m -> [32m0[m bytes
 .../urllib3/contrib/emscripten/connection.py       |    259 [31m-[m
 .../contrib/emscripten/emscripten_fetch_worker.js  |    110 [31m-[m
 .../urllib3/contrib/emscripten/fetch.py            |    726 [31m-[m
 .../urllib3/contrib/emscripten/request.py          |     22 [31m-[m
 .../urllib3/contrib/emscripten/response.py         |    277 [31m-[m
 .../Lib/site-packages/urllib3/contrib/pyopenssl.py |    564 [31m-[m
 .../Lib/site-packages/urllib3/contrib/socks.py     |    228 [31m-[m
 .../venv/Lib/site-packages/urllib3/exceptions.py   |    335 [31m-[m
 backend/venv/Lib/site-packages/urllib3/fields.py   |    341 [31m-[m
 backend/venv/Lib/site-packages/urllib3/filepost.py |     89 [31m-[m
 .../Lib/site-packages/urllib3/http2/__init__.py    |     53 [31m-[m
 .../http2/__pycache__/__init__.cpython-312.pyc     |    Bin [31m1730[m -> [32m0[m bytes
 .../http2/__pycache__/connection.cpython-312.pyc   |    Bin [31m16951[m -> [32m0[m bytes
 .../http2/__pycache__/probe.cpython-312.pyc        |    Bin [31m3641[m -> [32m0[m bytes
 .../Lib/site-packages/urllib3/http2/connection.py  |    356 [31m-[m
 .../venv/Lib/site-packages/urllib3/http2/probe.py  |     87 [31m-[m
 .../venv/Lib/site-packages/urllib3/poolmanager.py  |    651 [31m-[m
 backend/venv/Lib/site-packages/urllib3/py.typed    |      2 [31m-[m
 backend/venv/Lib/site-packages/urllib3/response.py |   1476 [31m-[m
 .../Lib/site-packages/urllib3/util/__init__.py     |     42 [31m-[m
 .../util/__pycache__/__init__.cpython-312.pyc      |    Bin [31m990[m -> [32m0[m bytes
 .../util/__pycache__/connection.cpython-312.pyc    |    Bin [31m4671[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/proxy.cpython-312.pyc |    Bin [31m1202[m -> [32m0[m bytes
 .../util/__pycache__/request.cpython-312.pyc       |    Bin [31m8326[m -> [32m0[m bytes
 .../util/__pycache__/response.cpython-312.pyc      |    Bin [31m2861[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/retry.cpython-312.pyc |    Bin [31m20276[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/ssl_.cpython-312.pyc  |    Bin [31m17290[m -> [32m0[m bytes
 .../__pycache__/ssl_match_hostname.cpython-312.pyc |    Bin [31m5522[m -> [32m0[m bytes
 .../util/__pycache__/ssltransport.cpython-312.pyc  |    Bin [31m13290[m -> [32m0[m bytes
 .../util/__pycache__/timeout.cpython-312.pyc       |    Bin [31m11674[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/url.cpython-312.pyc   |    Bin [31m16205[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/util.cpython-312.pyc  |    Bin [31m1979[m -> [32m0[m bytes
 .../urllib3/util/__pycache__/wait.cpython-312.pyc  |    Bin [31m3425[m -> [32m0[m bytes
 .../Lib/site-packages/urllib3/util/connection.py   |    137 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/proxy.py   |     43 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/request.py |    263 [31m-[m
 .../Lib/site-packages/urllib3/util/response.py     |    101 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/retry.py   |    533 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/ssl_.py    |    527 [31m-[m
 .../urllib3/util/ssl_match_hostname.py             |    159 [31m-[m
 .../Lib/site-packages/urllib3/util/ssltransport.py |    271 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/timeout.py |    275 [31m-[m
 backend/venv/Lib/site-packages/urllib3/util/url.py |    469 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/util.py    |     42 [31m-[m
 .../venv/Lib/site-packages/urllib3/util/wait.py    |    124 [31m-[m
 .../uvicorn-0.40.0.dist-info/INSTALLER             |      1 [31m-[m
 .../uvicorn-0.40.0.dist-info/METADATA              |    191 [31m-[m
 .../site-packages/uvicorn-0.40.0.dist-info/RECORD  |     89 [31m-[m
 .../uvicorn-0.40.0.dist-info/REQUESTED             |      0
 .../site-packages/uvicorn-0.40.0.dist-info/WHEEL   |      4 [31m-[m
 .../uvicorn-0.40.0.dist-info/entry_points.txt      |      2 [31m-[m
 .../uvicorn-0.40.0.dist-info/licenses/LICENSE.md   |     27 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/__init__.py |      5 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/__main__.py |      4 [31m-[m
 .../uvicorn/__pycache__/__init__.cpython-312.pyc   |    Bin [31m367[m -> [32m0[m bytes
 .../uvicorn/__pycache__/__main__.cpython-312.pyc   |    Bin [31m287[m -> [32m0[m bytes
 .../uvicorn/__pycache__/_compat.cpython-312.pyc    |    Bin [31m3985[m -> [32m0[m bytes
 .../__pycache__/_subprocess.cpython-312.pyc        |    Bin [31m2930[m -> [32m0[m bytes
 .../uvicorn/__pycache__/_types.cpython-312.pyc     |    Bin [31m11398[m -> [32m0[m bytes
 .../uvicorn/__pycache__/config.cpython-312.pyc     |    Bin [31m25887[m -> [32m0[m bytes
 .../uvicorn/__pycache__/importer.cpython-312.pyc   |    Bin [31m1760[m -> [32m0[m bytes
 .../uvicorn/__pycache__/logging.cpython-312.pyc    |    Bin [31m7769[m -> [32m0[m bytes
 .../uvicorn/__pycache__/main.cpython-312.pyc       |    Bin [31m20980[m -> [32m0[m bytes
 .../uvicorn/__pycache__/server.cpython-312.pyc     |    Bin [31m16691[m -> [32m0[m bytes
 .../uvicorn/__pycache__/workers.cpython-312.pyc    |    Bin [31m6548[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/uvicorn/_compat.py  |     91 [31m-[m
 .../venv/Lib/site-packages/uvicorn/_subprocess.py  |     84 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/_types.py   |    274 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/config.py   |    549 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/importer.py |     34 [31m-[m
 .../Lib/site-packages/uvicorn/lifespan/__init__.py |      0
 .../lifespan/__pycache__/__init__.cpython-312.pyc  |    Bin [31m178[m -> [32m0[m bytes
 .../lifespan/__pycache__/off.cpython-312.pyc       |    Bin [31m967[m -> [32m0[m bytes
 .../lifespan/__pycache__/on.cpython-312.pyc        |    Bin [31m7926[m -> [32m0[m bytes
 .../venv/Lib/site-packages/uvicorn/lifespan/off.py |     17 [31m-[m
 .../venv/Lib/site-packages/uvicorn/lifespan/on.py  |    137 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/logging.py  |    117 [31m-[m
 .../Lib/site-packages/uvicorn/loops/__init__.py    |      0
 .../loops/__pycache__/__init__.cpython-312.pyc     |    Bin [31m175[m -> [32m0[m bytes
 .../loops/__pycache__/asyncio.cpython-312.pyc      |    Bin [31m707[m -> [32m0[m bytes
 .../uvicorn/loops/__pycache__/auto.cpython-312.pyc |    Bin [31m807[m -> [32m0[m bytes
 .../loops/__pycache__/uvloop.cpython-312.pyc       |    Bin [31m564[m -> [32m0[m bytes
 .../Lib/site-packages/uvicorn/loops/asyncio.py     |     11 [31m-[m
 .../venv/Lib/site-packages/uvicorn/loops/auto.py   |     17 [31m-[m
 .../venv/Lib/site-packages/uvicorn/loops/uvloop.py |     10 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/main.py     |    618 [31m-[m
 .../site-packages/uvicorn/middleware/__init__.py   |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m180[m -> [32m0[m bytes
 .../middleware/__pycache__/asgi2.cpython-312.pyc   |    Bin [31m990[m -> [32m0[m bytes
 .../__pycache__/message_logger.cpython-312.pyc     |    Bin [31m4381[m -> [32m0[m bytes
 .../__pycache__/proxy_headers.cpython-312.pyc      |    Bin [31m5800[m -> [32m0[m bytes
 .../middleware/__pycache__/wsgi.cpython-312.pyc    |    Bin [31m9921[m -> [32m0[m bytes
 .../Lib/site-packages/uvicorn/middleware/asgi2.py  |     15 [31m-[m
 .../uvicorn/middleware/message_logger.py           |     87 [31m-[m
 .../uvicorn/middleware/proxy_headers.py            |    142 [31m-[m
 .../Lib/site-packages/uvicorn/middleware/wsgi.py   |    199 [31m-[m
 .../site-packages/uvicorn/protocols/__init__.py    |      0
 .../protocols/__pycache__/__init__.cpython-312.pyc |    Bin [31m179[m -> [32m0[m bytes
 .../protocols/__pycache__/utils.cpython-312.pyc    |    Bin [31m2950[m -> [32m0[m bytes
 .../uvicorn/protocols/http/__init__.py             |      0
 .../http/__pycache__/__init__.cpython-312.pyc      |    Bin [31m184[m -> [32m0[m bytes
 .../http/__pycache__/auto.cpython-312.pyc          |    Bin [31m595[m -> [32m0[m bytes
 .../http/__pycache__/flow_control.cpython-312.pyc  |    Bin [31m3025[m -> [32m0[m bytes
 .../http/__pycache__/h11_impl.cpython-312.pyc      |    Bin [31m27166[m -> [32m0[m bytes
 .../__pycache__/httptools_impl.cpython-312.pyc     |    Bin [31m29169[m -> [32m0[m bytes
 .../site-packages/uvicorn/protocols/http/auto.py   |     15 [31m-[m
 .../uvicorn/protocols/http/flow_control.py         |     54 [31m-[m
 .../uvicorn/protocols/http/h11_impl.py             |    550 [31m-[m
 .../uvicorn/protocols/http/httptools_impl.py       |    577 [31m-[m
 .../Lib/site-packages/uvicorn/protocols/utils.py   |     56 [31m-[m
 .../uvicorn/protocols/websockets/__init__.py       |      0
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m190[m -> [32m0[m bytes
 .../websockets/__pycache__/auto.cpython-312.pyc    |    Bin [31m799[m -> [32m0[m bytes
 .../__pycache__/websockets_impl.cpython-312.pyc    |    Bin [31m20289[m -> [32m0[m bytes
 .../websockets_sansio_impl.cpython-312.pyc         |    Bin [31m24368[m -> [32m0[m bytes
 .../__pycache__/wsproto_impl.cpython-312.pyc       |    Bin [31m20861[m -> [32m0[m bytes
 .../uvicorn/protocols/websockets/auto.py           |     21 [31m-[m
 .../protocols/websockets/websockets_impl.py        |    384 [31m-[m
 .../protocols/websockets/websockets_sansio_impl.py |    415 [31m-[m
 .../uvicorn/protocols/websockets/wsproto_impl.py   |    375 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/py.typed    |      1 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/server.py   |    338 [31m-[m
 .../site-packages/uvicorn/supervisors/__init__.py  |     16 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m744[m -> [32m0[m bytes
 .../__pycache__/basereload.cpython-312.pyc         |    Bin [31m7016[m -> [32m0[m bytes
 .../__pycache__/multiprocess.cpython-312.pyc       |    Bin [31m13435[m -> [32m0[m bytes
 .../__pycache__/statreload.cpython-312.pyc         |    Bin [31m2810[m -> [32m0[m bytes
 .../__pycache__/watchfilesreload.cpython-312.pyc   |    Bin [31m4230[m -> [32m0[m bytes
 .../uvicorn/supervisors/basereload.py              |    125 [31m-[m
 .../uvicorn/supervisors/multiprocess.py            |    223 [31m-[m
 .../uvicorn/supervisors/statreload.py              |     52 [31m-[m
 .../uvicorn/supervisors/watchfilesreload.py        |     85 [31m-[m
 backend/venv/Lib/site-packages/uvicorn/workers.py  |    111 [31m-[m
 .../watchfiles-1.1.1.dist-info/INSTALLER           |      1 [31m-[m
 .../watchfiles-1.1.1.dist-info/METADATA            |    148 [31m-[m
 .../watchfiles-1.1.1.dist-info/RECORD              |     24 [31m-[m
 .../site-packages/watchfiles-1.1.1.dist-info/WHEEL |      4 [31m-[m
 .../watchfiles-1.1.1.dist-info/entry_points.txt    |      2 [31m-[m
 .../watchfiles-1.1.1.dist-info/licenses/LICENSE    |     21 [31m-[m
 .../venv/Lib/site-packages/watchfiles/__init__.py  |     17 [31m-[m
 .../venv/Lib/site-packages/watchfiles/__main__.py  |      4 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m531[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m265[m -> [32m0[m bytes
 .../watchfiles/__pycache__/cli.cpython-312.pyc     |    Bin [31m10183[m -> [32m0[m bytes
 .../watchfiles/__pycache__/filters.cpython-312.pyc |    Bin [31m7206[m -> [32m0[m bytes
 .../watchfiles/__pycache__/main.cpython-312.pyc    |    Bin [31m17103[m -> [32m0[m bytes
 .../watchfiles/__pycache__/run.cpython-312.pyc     |    Bin [31m19461[m -> [32m0[m bytes
 .../watchfiles/__pycache__/version.cpython-312.pyc |    Bin [31m265[m -> [32m0[m bytes
 .../watchfiles/_rust_notify.cp312-win_amd64.pyd    |    Bin [31m685568[m -> [32m0[m bytes
 .../Lib/site-packages/watchfiles/_rust_notify.pyi  |    111 [31m-[m
 backend/venv/Lib/site-packages/watchfiles/cli.py   |    224 [31m-[m
 .../venv/Lib/site-packages/watchfiles/filters.py   |    149 [31m-[m
 backend/venv/Lib/site-packages/watchfiles/main.py  |    373 [31m-[m
 backend/venv/Lib/site-packages/watchfiles/py.typed |      1 [31m-[m
 backend/venv/Lib/site-packages/watchfiles/run.py   |    438 [31m-[m
 .../venv/Lib/site-packages/watchfiles/version.py   |      5 [31m-[m
 .../websockets-15.0.1.dist-info/INSTALLER          |      1 [31m-[m
 .../websockets-15.0.1.dist-info/LICENSE            |     24 [31m-[m
 .../websockets-15.0.1.dist-info/METADATA           |    179 [31m-[m
 .../websockets-15.0.1.dist-info/RECORD             |    106 [31m-[m
 .../websockets-15.0.1.dist-info/WHEEL              |      5 [31m-[m
 .../websockets-15.0.1.dist-info/entry_points.txt   |      2 [31m-[m
 .../websockets-15.0.1.dist-info/top_level.txt      |      1 [31m-[m
 .../venv/Lib/site-packages/websockets/__init__.py  |    236 [31m-[m
 .../venv/Lib/site-packages/websockets/__main__.py  |      5 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m4473[m -> [32m0[m bytes
 .../__pycache__/__main__.cpython-312.pyc           |    Bin [31m273[m -> [32m0[m bytes
 .../websockets/__pycache__/auth.cpython-312.pyc    |    Bin [31m785[m -> [32m0[m bytes
 .../websockets/__pycache__/cli.cpython-312.pyc     |    Bin [31m8301[m -> [32m0[m bytes
 .../websockets/__pycache__/client.cpython-312.pyc  |    Bin [31m16148[m -> [32m0[m bytes
 .../__pycache__/connection.cpython-312.pyc         |    Bin [31m541[m -> [32m0[m bytes
 .../__pycache__/datastructures.cpython-312.pyc     |    Bin [31m8895[m -> [32m0[m bytes
 .../__pycache__/exceptions.cpython-312.pyc         |    Bin [31m17918[m -> [32m0[m bytes
 .../websockets/__pycache__/frames.cpython-312.pyc  |    Bin [31m15996[m -> [32m0[m bytes
 .../websockets/__pycache__/headers.cpython-312.pyc |    Bin [31m18128[m -> [32m0[m bytes
 .../websockets/__pycache__/http.cpython-312.pyc    |    Bin [31m897[m -> [32m0[m bytes
 .../websockets/__pycache__/http11.cpython-312.pyc  |    Bin [31m15467[m -> [32m0[m bytes
 .../websockets/__pycache__/imports.cpython-312.pyc |    Bin [31m3396[m -> [32m0[m bytes
 .../__pycache__/protocol.cpython-312.pyc           |    Bin [31m25383[m -> [32m0[m bytes
 .../websockets/__pycache__/server.cpython-312.pyc  |    Bin [31m23038[m -> [32m0[m bytes
 .../websockets/__pycache__/streams.cpython-312.pyc |    Bin [31m5435[m -> [32m0[m bytes
 .../websockets/__pycache__/typing.cpython-312.pyc  |    Bin [31m1242[m -> [32m0[m bytes
 .../websockets/__pycache__/uri.cpython-312.pyc     |    Bin [31m8108[m -> [32m0[m bytes
 .../websockets/__pycache__/utils.cpython-312.pyc   |    Bin [31m2218[m -> [32m0[m bytes
 .../websockets/__pycache__/version.cpython-312.pyc |    Bin [31m2966[m -> [32m0[m bytes
 .../site-packages/websockets/asyncio/__init__.py   |      0
 .../asyncio/__pycache__/__init__.cpython-312.pyc   |    Bin [31m180[m -> [32m0[m bytes
 .../__pycache__/async_timeout.cpython-312.pyc      |    Bin [31m10621[m -> [32m0[m bytes
 .../asyncio/__pycache__/client.cpython-312.pyc     |    Bin [31m33656[m -> [32m0[m bytes
 .../__pycache__/compatibility.cpython-312.pyc      |    Bin [31m1056[m -> [32m0[m bytes
 .../asyncio/__pycache__/connection.cpython-312.pyc |    Bin [31m51668[m -> [32m0[m bytes
 .../asyncio/__pycache__/messages.cpython-312.pyc   |    Bin [31m13578[m -> [32m0[m bytes
 .../asyncio/__pycache__/router.cpython-312.pyc     |    Bin [31m8171[m -> [32m0[m bytes
 .../asyncio/__pycache__/server.cpython-312.pyc     |    Bin [31m39225[m -> [32m0[m bytes
 .../websockets/asyncio/async_timeout.py            |    282 [31m-[m
 .../Lib/site-packages/websockets/asyncio/client.py |    820 [31m-[m
 .../websockets/asyncio/compatibility.py            |     30 [31m-[m
 .../site-packages/websockets/asyncio/connection.py |   1237 [31m-[m
 .../site-packages/websockets/asyncio/messages.py   |    314 [31m-[m
 .../Lib/site-packages/websockets/asyncio/router.py |    198 [31m-[m
 .../Lib/site-packages/websockets/asyncio/server.py |    981 [31m-[m
 backend/venv/Lib/site-packages/websockets/auth.py  |     18 [31m-[m
 backend/venv/Lib/site-packages/websockets/cli.py   |    178 [31m-[m
 .../venv/Lib/site-packages/websockets/client.py    |    389 [31m-[m
 .../Lib/site-packages/websockets/connection.py     |     12 [31m-[m
 .../Lib/site-packages/websockets/datastructures.py |    187 [31m-[m
 .../Lib/site-packages/websockets/exceptions.py     |    473 [31m-[m
 .../websockets/extensions/__init__.py              |      4 [31m-[m
 .../__pycache__/__init__.cpython-312.pyc           |    Bin [31m295[m -> [32m0[m bytes
 .../extensions/__pycache__/base.cpython-312.pyc    |    Bin [31m3909[m -> [32m0[m bytes
 .../__pycache__/permessage_deflate.cpython-312.pyc |    Bin [31m19426[m -> [32m0[m bytes
 .../site-packages/websockets/extensions/base.py    |    123 [31m-[m
 .../websockets/extensions/permessage_deflate.py    |    697 [31m-[m
 .../venv/Lib/site-packages/websockets/frames.py    |    430 [31m-[m
 .../venv/Lib/site-packages/websockets/headers.py   |    586 [31m-[m
 backend/venv/Lib/site-packages/websockets/http.py  |     20 [31m-[m
 .../venv/Lib/site-packages/websockets/http11.py    |    427 [31m-[m
 .../venv/Lib/site-packages/websockets/imports.py   |    100 [31m-[m
 .../site-packages/websockets/legacy/__init__.py    |     11 [31m-[m
 .../legacy/__pycache__/__init__.cpython-312.pyc    |    Bin [31m465[m -> [32m0[m bytes
 .../legacy/__pycache__/auth.cpython-312.pyc        |    Bin [31m7680[m -> [32m0[m bytes
 .../legacy/__pycache__/client.cpython-312.pyc      |    Bin [31m27831[m -> [32m0[m bytes
 .../legacy/__pycache__/exceptions.cpython-312.pyc  |    Bin [31m3313[m -> [32m0[m bytes
 .../legacy/__pycache__/framing.cpython-312.pyc     |    Bin [31m8175[m -> [32m0[m bytes
 .../legacy/__pycache__/handshake.cpython-312.pyc   |    Bin [31m6324[m -> [32m0[m bytes
 .../legacy/__pycache__/http.cpython-312.pyc        |    Bin [31m7682[m -> [32m0[m bytes
 .../legacy/__pycache__/protocol.cpython-312.pyc    |    Bin [31m63986[m -> [32m0[m bytes
 .../legacy/__pycache__/server.cpython-312.pyc      |    Bin [31m46677[m -> [32m0[m bytes
 .../Lib/site-packages/websockets/legacy/auth.py    |    190 [31m-[m
 .../Lib/site-packages/websockets/legacy/client.py  |    705 [31m-[m
 .../site-packages/websockets/legacy/exceptions.py  |     71 [31m-[m
 .../Lib/site-packages/websockets/legacy/framing.py |    225 [31m-[m
 .../site-packages/websockets/legacy/handshake.py   |    158 [31m-[m
 .../Lib/site-packages/websockets/legacy/http.py    |    201 [31m-[m
 .../site-packages/websockets/legacy/protocol.py    |   1641 [31m-[m
 .../Lib/site-packages/websockets/legacy/server.py  |   1191 [31m-[m
 .../venv/Lib/site-packages/websockets/protocol.py  |    758 [31m-[m
 backend/venv/Lib/site-packages/websockets/py.typed |      0
 .../venv/Lib/site-packages/websockets/server.py    |    587 [31m-[m
 .../venv/Lib/site-packages/websockets/speedups.c   |    222 [31m-[m
 .../websockets/speedups.cp312-win_amd64.pyd        |    Bin [31m11776[m -> [32m0[m bytes
 .../venv/Lib/site-packages/websockets/speedups.pyi |      1 [31m-[m
 .../venv/Lib/site-packages/websockets/streams.py   |    151 [31m-[m
 .../Lib/site-packages/websockets/sync/__init__.py  |      0
 .../sync/__pycache__/__init__.cpython-312.pyc      |    Bin [31m177[m -> [32m0[m bytes
 .../sync/__pycache__/client.cpython-312.pyc        |    Bin [31m24584[m -> [32m0[m bytes
 .../sync/__pycache__/connection.cpython-312.pyc    |    Bin [31m39767[m -> [32m0[m bytes
 .../sync/__pycache__/messages.cpython-312.pyc      |    Bin [31m13453[m -> [32m0[m bytes
 .../sync/__pycache__/router.cpython-312.pyc        |    Bin [31m7853[m -> [32m0[m bytes
 .../sync/__pycache__/server.cpython-312.pyc        |    Bin [31m28341[m -> [32m0[m bytes
 .../sync/__pycache__/utils.cpython-312.pyc         |    Bin [31m1646[m -> [32m0[m bytes
 .../Lib/site-packages/websockets/sync/client.py    |    648 [31m-[m
 .../site-packages/websockets/sync/connection.py    |   1072 [31m-[m
 .../Lib/site-packages/websockets/sync/messages.py  |    345 [31m-[m
 .../Lib/site-packages/websockets/sync/router.py    |    192 [31m-[m
 .../Lib/site-packages/websockets/sync/server.py    |    763 [31m-[m
 .../Lib/site-packages/websockets/sync/utils.py     |     45 [31m-[m
 .../venv/Lib/site-packages/websockets/typing.py    |     74 [31m-[m
 backend/venv/Lib/site-packages/websockets/uri.py   |    225 [31m-[m
 backend/venv/Lib/site-packages/websockets/utils.py |     51 [31m-[m
 .../venv/Lib/site-packages/websockets/version.py   |     92 [31m-[m
 backend/venv/Lib/site-packages/yaml/__init__.py    |    390 [31m-[m
 .../yaml/__pycache__/__init__.cpython-312.pyc      |    Bin [31m15581[m -> [32m0[m bytes
 .../yaml/__pycache__/composer.cpython-312.pyc      |    Bin [31m6512[m -> [32m0[m bytes
 .../yaml/__pycache__/constructor.cpython-312.pyc   |    Bin [31m34834[m -> [32m0[m bytes
 .../yaml/__pycache__/cyaml.cpython-312.pyc         |    Bin [31m4613[m -> [32m0[m bytes
 .../yaml/__pycache__/dumper.cpython-312.pyc        |    Bin [31m2449[m -> [32m0[m bytes
 .../yaml/__pycache__/emitter.cpython-312.pyc       |    Bin [31m50096[m -> [32m0[m bytes
 .../yaml/__pycache__/error.cpython-312.pyc         |    Bin [31m4255[m -> [32m0[m bytes
 .../yaml/__pycache__/events.cpython-312.pyc        |    Bin [31m4703[m -> [32m0[m bytes
 .../yaml/__pycache__/loader.cpython-312.pyc        |    Bin [31m3511[m -> [32m0[m bytes
 .../yaml/__pycache__/nodes.cpython-312.pyc         |    Bin [31m2196[m -> [32m0[m bytes
 .../yaml/__pycache__/parser.cpython-312.pyc        |    Bin [31m24691[m -> [32m0[m bytes
 .../yaml/__pycache__/reader.cpython-312.pyc        |    Bin [31m8831[m -> [32m0[m bytes
 .../yaml/__pycache__/representer.cpython-312.pyc   |    Bin [31m16885[m -> [32m0[m bytes
 .../yaml/__pycache__/resolver.cpython-312.pyc      |    Bin [31m9012[m -> [32m0[m bytes
 .../yaml/__pycache__/scanner.cpython-312.pyc       |    Bin [31m49812[m -> [32m0[m bytes
 .../yaml/__pycache__/serializer.cpython-312.pyc    |    Bin [31m6166[m -> [32m0[m bytes
 .../yaml/__pycache__/tokens.cpython-312.pyc        |    Bin [31m5770[m -> [32m0[m bytes
 .../site-packages/yaml/_yaml.cp312-win_amd64.pyd   |    Bin [31m253952[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/yaml/composer.py    |    139 [31m-[m
 backend/venv/Lib/site-packages/yaml/constructor.py |    748 [31m-[m
 backend/venv/Lib/site-packages/yaml/cyaml.py       |    101 [31m-[m
 backend/venv/Lib/site-packages/yaml/dumper.py      |     62 [31m-[m
 backend/venv/Lib/site-packages/yaml/emitter.py     |   1137 [31m-[m
 backend/venv/Lib/site-packages/yaml/error.py       |     75 [31m-[m
 backend/venv/Lib/site-packages/yaml/events.py      |     86 [31m-[m
 backend/venv/Lib/site-packages/yaml/loader.py      |     63 [31m-[m
 backend/venv/Lib/site-packages/yaml/nodes.py       |     49 [31m-[m
 backend/venv/Lib/site-packages/yaml/parser.py      |    589 [31m-[m
 backend/venv/Lib/site-packages/yaml/reader.py      |    185 [31m-[m
 backend/venv/Lib/site-packages/yaml/representer.py |    389 [31m-[m
 backend/venv/Lib/site-packages/yaml/resolver.py    |    227 [31m-[m
 backend/venv/Lib/site-packages/yaml/scanner.py     |   1435 [31m-[m
 backend/venv/Lib/site-packages/yaml/serializer.py  |    111 [31m-[m
 backend/venv/Lib/site-packages/yaml/tokens.py      |    104 [31m-[m
 .../site-packages/yarl-1.22.0.dist-info/INSTALLER  |      1 [31m-[m
 .../site-packages/yarl-1.22.0.dist-info/METADATA   |   2478 [31m-[m
 .../Lib/site-packages/yarl-1.22.0.dist-info/RECORD |     26 [31m-[m
 .../Lib/site-packages/yarl-1.22.0.dist-info/WHEEL  |      5 [31m-[m
 .../yarl-1.22.0.dist-info/licenses/LICENSE         |    202 [31m-[m
 .../yarl-1.22.0.dist-info/licenses/NOTICE          |     13 [31m-[m
 .../yarl-1.22.0.dist-info/top_level.txt            |      1 [31m-[m
 backend/venv/Lib/site-packages/yarl/__init__.py    |     14 [31m-[m
 .../yarl/__pycache__/__init__.cpython-312.pyc      |    Bin [31m446[m -> [32m0[m bytes
 .../yarl/__pycache__/_parse.cpython-312.pyc        |    Bin [31m6933[m -> [32m0[m bytes
 .../yarl/__pycache__/_path.cpython-312.pyc         |    Bin [31m1386[m -> [32m0[m bytes
 .../yarl/__pycache__/_query.cpython-312.pyc        |    Bin [31m4988[m -> [32m0[m bytes
 .../yarl/__pycache__/_quoters.cpython-312.pyc      |    Bin [31m1977[m -> [32m0[m bytes
 .../yarl/__pycache__/_quoting.cpython-312.pyc      |    Bin [31m740[m -> [32m0[m bytes
 .../yarl/__pycache__/_quoting_py.cpython-312.pyc   |    Bin [31m8795[m -> [32m0[m bytes
 .../yarl/__pycache__/_url.cpython-312.pyc          |    Bin [31m60775[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/yarl/_parse.py      |    203 [31m-[m
 backend/venv/Lib/site-packages/yarl/_path.py       |     41 [31m-[m
 backend/venv/Lib/site-packages/yarl/_query.py      |    121 [31m-[m
 backend/venv/Lib/site-packages/yarl/_quoters.py    |     33 [31m-[m
 backend/venv/Lib/site-packages/yarl/_quoting.py    |     19 [31m-[m
 .../yarl/_quoting_c.cp312-win_amd64.pyd            |    Bin [31m87040[m -> [32m0[m bytes
 backend/venv/Lib/site-packages/yarl/_quoting_c.pyx |    451 [31m-[m
 backend/venv/Lib/site-packages/yarl/_quoting_py.py |    213 [31m-[m
 backend/venv/Lib/site-packages/yarl/_url.py        |   1622 [31m-[m
 backend/venv/Lib/site-packages/yarl/py.typed       |      1 [31m-[m
 backend/venv/Scripts/Activate.ps1                  |    528 [31m-[m
 backend/venv/Scripts/activate                      |     76 [31m-[m
 backend/venv/Scripts/activate.bat                  |     34 [31m-[m
 backend/venv/Scripts/alembic.exe                   |    Bin [31m108402[m -> [32m0[m bytes
 backend/venv/Scripts/deactivate.bat                |     22 [31m-[m
 backend/venv/Scripts/distro.exe                    |    Bin [31m108401[m -> [32m0[m bytes
 backend/venv/Scripts/dotenv.exe                    |    Bin [31m108401[m -> [32m0[m bytes
 backend/venv/Scripts/email_validator.exe           |    Bin [31m108412[m -> [32m0[m bytes
 backend/venv/Scripts/fastapi.exe                   |    Bin [31m108399[m -> [32m0[m bytes
 backend/venv/Scripts/hf.exe                        |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/httpx.exe                     |    Bin [31m108393[m -> [32m0[m bytes
 backend/venv/Scripts/mako-render.exe               |    Bin [31m108402[m -> [32m0[m bytes
 backend/venv/Scripts/normalizer.exe                |    Bin [31m108422[m -> [32m0[m bytes
 backend/venv/Scripts/pip.exe                       |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/pip3.12.exe                   |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/pip3.exe                      |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/py.test.exe                   |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/pygmentize.exe                |    Bin [31m108404[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-decrypt.exe             |    Bin [31m108401[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-encrypt.exe             |    Bin [31m108401[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-keygen.exe              |    Bin [31m108399[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-priv2pub.exe            |    Bin [31m108422[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-sign.exe                |    Bin [31m108395[m -> [32m0[m bytes
 backend/venv/Scripts/pyrsa-verify.exe              |    Bin [31m108399[m -> [32m0[m bytes
 backend/venv/Scripts/pytest.exe                    |    Bin [31m108410[m -> [32m0[m bytes
 backend/venv/Scripts/python.exe                    |    Bin [31m274424[m -> [32m0[m bytes
 backend/venv/Scripts/pythonw.exe                   |    Bin [31m263400[m -> [32m0[m bytes
 backend/venv/Scripts/rq.exe                        |    Bin [31m108394[m -> [32m0[m bytes
 backend/venv/Scripts/rqinfo.exe                    |    Bin [31m108394[m -> [32m0[m bytes
 backend/venv/Scripts/rqworker.exe                  |    Bin [31m108398[m -> [32m0[m bytes
 backend/venv/Scripts/tiny-agents.exe               |    Bin [31m108420[m -> [32m0[m bytes
 backend/venv/Scripts/tqdm.exe                      |    Bin [31m108396[m -> [32m0[m bytes
 backend/venv/Scripts/uvicorn.exe                   |    Bin [31m108400[m -> [32m0[m bytes
 backend/venv/Scripts/watchfiles.exe                |    Bin [31m108400[m -> [32m0[m bytes
 backend/venv/Scripts/websockets.exe                |    Bin [31m108402[m -> [32m0[m bytes
 backend/venv/pyvenv.cfg                            |      5 [31m-[m
 10238 files changed, 4141547 deletions(-)
