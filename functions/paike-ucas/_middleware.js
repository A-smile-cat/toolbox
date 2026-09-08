/* ============================================================
   /paike-ucas/* 服务端口令门禁（Cloudflare Pages Functions）
   - 密码从环境变量 PAIKE_PASSWORD 读取（Dashboard → Settings →
     Variables and Secrets 配置），不进代码、不进 git。
   - 未通过校验时连 HTML 都不会返回，只返回登录页。
   - 校验通过发 HttpOnly cookie，24 小时内免重复输入。
   ============================================================ */

const AUTH_COOKIE = "paike.auth";
const COOKIE_MAX_AGE = 86400; // 24h，单位秒

function loginPage(status, errMsg) {
    const errHtml = errMsg
        ? `<div class="gate-err">${errMsg}</div>`
        : "";
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>选课排课表 · 访问口令</title>
<style>
  :root{
    --paper:#f6efe1; --card:#fdf8ec; --ink:#2b2417; --ink-2:#6f6350;
    --rule-2:#cbb98f; --red:#a93b2c; --red-deep:#7d2417;
    --serif:"Noto Serif SC","Source Han Serif SC","Songti SC","STSong","SimSun",serif;
  }
  *{ box-sizing:border-box; margin:0; padding:0; }
  body{
    min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:var(--paper); font-family:var(--serif); color:var(--ink);
  }
  .gate-card{
    background:var(--card); border:2px solid var(--ink); border-radius:8px;
    box-shadow:0 10px 40px rgba(43,36,23,.25);
    padding:34px 36px 30px; width:min(380px,90vw);
  }
  .gate-seal{
    width:46px; height:46px; margin:0 auto 14px;
    background:var(--red); color:#fdf3e2; border-radius:8px; transform:rotate(-4deg);
    display:flex; align-items:center; justify-content:center;
    font-size:20px; line-height:1.1; letter-spacing:1px;
    box-shadow:inset 0 0 0 2px rgba(253,243,226,.35), 0 2px 6px rgba(125,36,23,.28);
    user-select:none;
  }
  h1{ font-size:19px; text-align:center; letter-spacing:3px; margin-bottom:6px; }
  .gate-sub{
    font-size:12px; color:var(--ink-2); text-align:center;
    letter-spacing:1.5px; margin-bottom:18px;
  }
  input{
    width:100%; padding:10px 12px; font-size:14px; font-family:var(--serif);
    color:var(--ink); background:#fffaf0;
    border:1.5px solid var(--rule-2); border-radius:4px; outline:none;
  }
  input:focus{ border-color:var(--red); box-shadow:0 0 0 3px rgba(169,59,44,.12); }
  button{
    width:100%; margin-top:14px; padding:10px; font-size:14px;
    letter-spacing:3px; cursor:pointer; color:#fdf3e2; background:var(--red);
    border:none; border-radius:4px; font-family:var(--serif); transition:background .15s;
  }
  button:hover{ background:var(--red-deep); }
  .gate-err{
    margin-top:10px; font-size:12.5px; color:var(--red);
    text-align:center; letter-spacing:1px;
  }
</style>
</head>
<body>
  <form class="gate-card" method="POST" autocomplete="off">
    <div class="gate-seal">排<br>课</div>
    <h1>选课排课表</h1>
    <div class="gate-sub">请输入访问口令</div>
    <input type="password" name="password" placeholder="访问口令" autofocus>
    <button type="submit">进 入</button>
    ${errHtml}
  </form>
</body>
</html>`;
    return new Response(html, {
        status,
        headers: { "Content-Type": "text/html; charset=utf-8" },
    });
}

function hasValidCookie(request) {
    const cookie = request.headers.get("Cookie") || "";
    return cookie.split(";").some(c => c.trim() === `${AUTH_COOKIE}=ok`);
}

export async function onRequest(context) {
    const { request, env, next } = context;
    const pwd = env.PAIKE_PASSWORD;

    /* 环境变量未配置时：明确报错提示，而不是放行 */
    if (!pwd) {
        return new Response(
            "未配置 PAIKE_PASSWORD 环境变量（Cloudflare Dashboard → Settings → Variables and Secrets）。",
            { status: 500, headers: { "Content-Type": "text/plain; charset=utf-8" } },
        );
    }

    /* 已有有效 cookie → 放行，返回静态页面 */
    if (hasValidCookie(request)) {
        return next();
    }

    /* POST 提交密码 → 校验 */
    if (request.method === "POST") {
        let submitted = "";
        try {
            const form = await request.formData();
            submitted = String(form.get("password") || "");
        } catch (e) {
            return loginPage(400, "表单解析失败，请重试");
        }
        if (submitted === pwd) {
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": "/paike-ucas/",
                    "Set-Cookie":
                        `${AUTH_COOKIE}=ok; Path=/paike-ucas; HttpOnly; Secure; ` +
                        `Max-Age=${COOKIE_MAX_AGE}; SameSite=Lax`,
                },
            });
        }
        return loginPage(401, "口令不正确，请重试");
    }

    /* 其余（GET 等）→ 登录页 */
    return loginPage(401, null);
}
