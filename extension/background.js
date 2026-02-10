const API_BASE = "https://ytgo.su"

let currentConfig = null

function buildPacScript(domains, host, port) {
  const normalized = Array.isArray(domains)
    ? domains.filter(Boolean)
    : []
  const hostPort = host + ":" + String(port || 1080)
  const list = normalized
    .map(function (d) {
      return '"' + d.replace(/"/g, "") + '"'
    })
    .join(",")

  const script =
    "var domains = [" +
    list +
    "];" +
    "function hostMatches(host) {" +
    "  for (var i = 0; i < domains.length; i++) {" +
    "    var d = domains[i];" +
    "    if (host === d || host.endsWith('.' + d)) return true;" +
    "  }" +
    "  return false;" +
    "}" +
    "function FindProxyForURL(url, host) {" +
    "  if (hostMatches(host)) return 'SOCKS5 " +
    hostPort +
    "; SOCKS " +
    hostPort +
    "; DIRECT';" +
    "  return 'DIRECT';" +
    "}"

  return script
}

function applyProxyConfig(config) {
  if (!config || !config.host || !config.port) {
    chrome.proxy.settings.clear({ scope: "regular" })
    currentConfig = null
    return
  }

  const pacScript = buildPacScript(
    config.domains || [],
    config.host,
    config.port
  )

  currentConfig = {
    host: config.host,
    port: config.port,
    username: config.username || "",
    password: config.password || "",
    domains: config.domains || []
  }

  chrome.proxy.settings.set(
    {
      value: {
        mode: "pac_script",
        pacScript: {
          data: pacScript
        }
      },
      scope: "regular"
    },
    function () {}
  )
}

function fetchProxyConfig() {
  fetch(API_BASE + "/api/proxy-config", {
    credentials: "include"
  })
    .then(function (res) {
      if (!res.ok) throw new Error("failed")
      return res.json()
    })
    .then(function (data) {
      applyProxyConfig(data)
    })
    .catch(function () {})
}

chrome.runtime.onInstalled.addListener(function () {
  fetchProxyConfig()
})

chrome.runtime.onStartup.addListener(function () {
  fetchProxyConfig()
})

chrome.webRequest.onAuthRequired.addListener(
  function (details, callback) {
    if (
      !currentConfig ||
      !currentConfig.username ||
      !currentConfig.password
    ) {
      return callback({})
    }

    if (!details.isProxy || !details.challenger) {
      return callback({})
    }

    callback({
      authCredentials: {
        username: currentConfig.username,
        password: currentConfig.password
      }
    })
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
)

