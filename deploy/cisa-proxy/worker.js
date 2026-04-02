const CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const ALLOWED_ORIGIN = "https://pkghawk.dev";

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    const ua = request.headers.get("User-Agent") || "";

    if (!ua.includes("pkghawk")) {
      return new Response("Forbidden", { status: 403 });
    }

    const resp = await fetch(CISA_URL, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; pkghawk/0.1; +https://pkghawk.dev)" },
    });

    const body = await resp.arrayBuffer();
    return new Response(body, {
      status: resp.status,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "public, max-age=3600",
      },
    });
  },
};
