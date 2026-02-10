const path = require("path")
const express = require("express")
const session = require("express-session")
const { Pool } = require("pg")
const passport = require("passport")
const GoogleStrategy = require("passport-google-oauth20").Strategy
const PgSession = require("connect-pg-simple")(session)
const cors = require("cors")
require("dotenv").config()

const app = express()

let dbPool

if (process.env.DATABASE_URL) {
  console.log("Connecting to DB via DATABASE_URL")
  dbPool = new Pool({
    connectionString: process.env.DATABASE_URL
  })
} else {
  const effectiveHost = process.env.POSTGRES_HOST || "db"
  console.log("Connecting to DB at:", effectiveHost)
  dbPool = new Pool({
    host: effectiveHost,
    port: Number(process.env.POSTGRES_PORT || 5432),
    database: process.env.POSTGRES_DB || "ytgo",
    user: process.env.POSTGRES_USER || "ytgo",
    password: process.env.POSTGRES_PASSWORD || "ytgo_password"
  })
}

const PLAN_DEFS = [
  {
    code: "trial",
    name: "Trial",
    price_rub: 0,
    duration_days: 7,
    max_quality: "720p",
    max_domains: 1,
    allow_custom_domain: false,
    family_extra_users: 0
  },
  {
    code: "daily",
    name: "Daily",
    price_rub: 5,
    duration_days: 1,
    max_quality: "720p",
    max_domains: 1,
    allow_custom_domain: true,
    family_extra_users: 0
  },
  {
    code: "monthly",
    name: "Monthly",
    price_rub: 100,
    duration_days: 30,
    max_quality: "1080p",
    max_domains: 3,
    allow_custom_domain: true,
    family_extra_users: 0
  },
  {
    code: "premium_3m",
    name: "Premium 3 months",
    price_rub: 249,
    duration_days: 90,
    max_quality: "4K HDR",
    max_domains: 5,
    allow_custom_domain: true,
    family_extra_users: 1
  },
  {
    code: "premium_6m",
    name: "Premium 6 months",
    price_rub: 399,
    duration_days: 180,
    max_quality: "4K HDR",
    max_domains: 5,
    allow_custom_domain: true,
    family_extra_users: 1
  },
  {
    code: "premium_12m",
    name: "Premium 12 months",
    price_rub: 699,
    duration_days: 365,
    max_quality: "4K HDR",
    max_domains: 5,
    allow_custom_domain: true,
    family_extra_users: 1
  }
]

async function initDb() {
  await dbPool.query(`
    create table if not exists subscription_tiers (
      code text primary key,
      name text not null,
      price_rub numeric(12,2) not null,
      duration_days integer not null,
      max_quality text not null,
      max_domains integer not null,
      allow_custom_domain boolean not null default false,
      family_extra_users integer not null default 0,
      created_at timestamptz not null default now()
    )
  `)

  await dbPool.query(`
    create table if not exists users (
      id serial primary key,
      google_id text unique,
      email text unique,
      name text,
      picture text,
      is_admin boolean not null default false,
      family_owner_id integer references users(id),
      created_at timestamptz not null default now()
    )
  `)

  await dbPool.query(`
    create table if not exists subscriptions (
      id serial primary key,
      user_id integer not null references users(id) on delete cascade,
      tier_code text not null references subscription_tiers(code),
      status text not null default 'active',
      start_at timestamptz not null,
      end_at timestamptz,
      created_at timestamptz not null default now()
    )
  `)

  await dbPool.query(`
    create table if not exists domains (
      id serial primary key,
      user_id integer not null references users(id) on delete cascade,
      domain text not null,
      created_at timestamptz not null default now(),
      unique (user_id, domain)
    )
  `)

  for (const plan of PLAN_DEFS) {
    await dbPool.query(
      `
        insert into subscription_tiers
          (code, name, price_rub, duration_days, max_quality, max_domains, allow_custom_domain, family_extra_users)
        values ($1,$2,$3,$4,$5,$6,$7,$8)
        on conflict (code) do update set
          name = excluded.name,
          price_rub = excluded.price_rub,
          duration_days = excluded.duration_days,
          max_quality = excluded.max_quality,
          max_domains = excluded.max_domains,
          allow_custom_domain = excluded.allow_custom_domain,
          family_extra_users = excluded.family_extra_users
      `,
      [
        plan.code,
        plan.name,
        plan.price_rub,
        plan.duration_days,
        plan.max_quality,
        plan.max_domains,
        plan.allow_custom_domain,
        plan.family_extra_users
      ]
    )
  }
}

async function getActiveSubscription(userId) {
  const result = await dbPool.query(
    `
      select s.*, t.name as plan_name, t.max_quality, t.max_domains, t.allow_custom_domain, t.family_extra_users, t.price_rub
      from subscriptions s
      join subscription_tiers t on t.code = s.tier_code
      where s.user_id = $1
        and s.status = 'active'
        and (s.end_at is null or s.end_at > now())
      order by s.end_at desc
      limit 1
    `,
    [userId]
  )
  return result.rows[0] || null
}

async function activateSubscription(userId, tierCode) {
  const client = await dbPool.connect()
  try {
    const tierResult = await client.query(
      "select * from subscription_tiers where code = $1",
      [tierCode]
    )
    if (tierResult.rows.length === 0) {
      throw new Error("Unknown subscription tier")
    }
    const tier = tierResult.rows[0]

    await client.query("begin")
    await client.query(
      "update subscriptions set status = 'expired' where user_id = $1 and status = 'active'",
      [userId]
    )

    const startAt = new Date()
    const endAt = new Date(
      startAt.getTime() + tier.duration_days * 24 * 60 * 60 * 1000
    )

    await client.query(
      `
        insert into subscriptions (user_id, tier_code, status, start_at, end_at)
        values ($1,$2,$3,$4,$5)
      `,
      [userId, tier.code, "active", startAt, endAt]
    )

    await client.query("commit")
  } catch (e) {
    await client.query("rollback")
    throw e
  } finally {
    client.release()
  }
}

function normalizeDomain(input) {
  if (!input) return null
  let domain = String(input).trim().toLowerCase()
  if (!domain) return null
  domain = domain.replace(/^https?:\/\//, "")
  domain = domain.replace(/\/.*$/, "")
  domain = domain.replace(/^\./, "")
  if (!domain) return null
  return domain
}

initDb()
  .then(() => {
    console.log("Database initialized")
  })
  .catch((err) => {
    console.error("Failed to initialize database", err)
    process.exit(1)
  })

app.use(
  cors({
    origin: true,
    credentials: true
  })
)

app.use(express.json())
app.use(
  session({
    store: new PgSession({
      pool: dbPool,
      tableName: "session"
    }),
    secret: process.env.SESSION_SECRET || "ytgo_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000
    }
  })
)

app.use(passport.initialize())
app.use(passport.session())

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (id, done) => {
  try {
    const result = await dbPool.query("select * from users where id = $1", [id])
    if (result.rows.length === 0) {
      return done(null, false)
    }
    done(null, result.rows[0])
  } catch (e) {
    done(e)
  }
})

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email =
          profile.emails && profile.emails[0] ? profile.emails[0].value : null

        let userResult = await dbPool.query(
          "select * from users where google_id = $1",
          [profile.id]
        )

        if (userResult.rows.length === 0 && email) {
          userResult = await dbPool.query(
            "select * from users where email = $1",
            [email]
          )
        }

        let user

        if (userResult.rows.length === 0) {
          const isAdmin =
            email && process.env.ADMIN_EMAIL
              ? email.toLowerCase() ===
                process.env.ADMIN_EMAIL.toLowerCase()
              : false

          const insertResult = await dbPool.query(
            `
              insert into users (google_id, email, name, picture, is_admin)
              values ($1,$2,$3,$4,$5)
              returning *
            `,
            [
              profile.id,
              email,
              profile.displayName,
              profile.photos && profile.photos[0]
                ? profile.photos[0].value
                : null,
              isAdmin
            ]
          )
          user = insertResult.rows[0]
        } else {
          user = userResult.rows[0]
          const isAdmin =
            email && process.env.ADMIN_EMAIL
              ? email.toLowerCase() ===
                process.env.ADMIN_EMAIL.toLowerCase()
              : user.is_admin

          const updateResult = await dbPool.query(
            `
              update users
              set google_id = $1,
                  email = coalesce($2, email),
                  name = $3,
                  picture = $4,
                  is_admin = $5
              where id = $6
              returning *
            `,
            [
              profile.id,
              email,
              profile.displayName,
              profile.photos && profile.photos[0]
                ? profile.photos[0].value
                : null,
              isAdmin,
              user.id
            ]
          )
          user = updateResult.rows[0]
        }

        const subscription = await getActiveSubscription(user.id)
        if (!subscription) {
          await activateSubscription(user.id, "trial")
        }

        done(null, user)
      } catch (e) {
        done(e)
      }
    }
  )
)

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next()
  }
  res.status(401).json({ error: "unauthorized" })
}

function requireAdmin(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "unauthorized" })
  }
  if (
    req.user &&
    req.user.email &&
    process.env.ADMIN_EMAIL &&
    req.user.email.toLowerCase() ===
      process.env.ADMIN_EMAIL.toLowerCase()
  ) {
    return next()
  }
  return res.status(403).json({ error: "forbidden" })
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
)

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/"
  }),
  (req, res) => {
    res.redirect("/")
  }
)

app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err)
    }
    req.session.destroy(() => {
      res.clearCookie("connect.sid")
      res.json({ ok: true })
    })
  })
})

app.get("/api/me", async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.json({ user: null })
  }

  const subscription = await getActiveSubscription(req.user.id)

  res.json({
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.picture,
      isAdmin: req.user.is_admin
    },
    subscription: subscription
      ? {
          tierCode: subscription.tier_code,
          planName: subscription.plan_name,
          status: subscription.status,
          startAt: subscription.start_at,
          endAt: subscription.end_at,
          maxQuality: subscription.max_quality,
          maxDomains: subscription.max_domains,
          allowCustomDomain: subscription.allow_custom_domain,
          familyExtraUsers: subscription.family_extra_users,
          priceRub: subscription.price_rub
        }
      : null
  })
})

app.get("/api/domains", requireAuth, async (req, res) => {
  const result = await dbPool.query(
    "select id, domain, created_at from domains where user_id = $1 order by created_at asc",
    [req.user.id]
  )
  res.json({ domains: result.rows })
})

app.post("/api/domains", requireAuth, async (req, res) => {
  const subscription = await getActiveSubscription(req.user.id)
  if (!subscription) {
    return res.status(403).json({ error: "no_active_subscription" })
  }

  const rawDomain = req.body && req.body.domain
  const domain = normalizeDomain(rawDomain)
  if (!domain) {
    return res.status(400).json({ error: "invalid_domain" })
  }

  const existing = await dbPool.query(
    "select count(*)::int as count from domains where user_id = $1",
    [req.user.id]
  )

  if (existing.rows[0].count >= subscription.max_domains) {
    return res.status(400).json({ error: "limit_reached" })
  }

  if (!subscription.allow_custom_domain) {
    const allowedList = [
      "youtube.com",
      "www.youtube.com",
      "youtu.be"
    ]
    if (!allowedList.includes(domain)) {
      return res
        .status(400)
        .json({ error: "custom_domain_not_allowed" })
    }
  }

  try {
    const insert = await dbPool.query(
      `
        insert into domains (user_id, domain)
        values ($1,$2)
        on conflict (user_id, domain) do nothing
        returning id, domain, created_at
      `,
      [req.user.id, domain]
    )

    if (insert.rows.length === 0) {
      return res
        .status(200)
        .json({ domain: { id: null, domain, exists: true } })
    }

    res.status(201).json({ domain: insert.rows[0] })
  } catch (e) {
    res.status(500).json({ error: "server_error" })
  }
})

app.delete("/api/domains/:id", requireAuth, async (req, res) => {
  const id = Number(req.params.id)
  if (!id) {
    return res.status(400).json({ error: "invalid_id" })
  }

  await dbPool.query(
    "delete from domains where id = $1 and user_id = $2",
    [id, req.user.id]
  )
  res.json({ ok: true })
})

app.get("/api/proxy-config", requireAuth, async (req, res) => {
  const subscription = await getActiveSubscription(req.user.id)
  if (!subscription) {
    return res.status(403).json({ error: "no_active_subscription" })
  }

  const domainsResult = await dbPool.query(
    "select domain from domains where user_id = $1 order by created_at asc",
    [req.user.id]
  )

  res.json({
    host: process.env.XRAY_SOCKS_HOST || "xray",
    port: Number(process.env.XRAY_SOCKS_PORT || 1080),
    username: process.env.XRAY_SOCKS_USER || "ytgo_user",
    password: process.env.XRAY_SOCKS_PASS || "ytgo_password",
    domains: domainsResult.rows.map((d) => d.domain)
  })
})

app.get("/secret-admin", requireAdmin, (req, res) => {
  res.send("YTGO admin")
})

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const result = await dbPool.query(`
    select
      u.id,
      u.email,
      u.name,
      u.picture,
      u.is_admin,
      u.created_at,
      s.tier_code,
      s.status,
      s.start_at,
      s.end_at,
      t.name as plan_name,
      t.max_domains,
      t.max_quality,
      t.allow_custom_domain,
      t.family_extra_users,
      array_remove(array_agg(d.domain), null) as domains
    from users u
    left join subscriptions s
      on s.user_id = u.id
      and s.status = 'active'
      and (s.end_at is null or s.end_at > now())
    left join subscription_tiers t
      on t.code = s.tier_code
    left join domains d
      on d.user_id = u.id
    group by
      u.id,
      s.id,
      t.code
    order by u.id asc
  `)

  res.json({ users: result.rows })
})

app.post(
  "/api/admin/users/:userId/extend",
  requireAdmin,
  async (req, res) => {
    const userId = Number(req.params.userId)
    if (!userId) {
      return res.status(400).json({ error: "invalid_user_id" })
    }

    const days = Number(req.body && req.body.days)
    const tierCode =
      (req.body && req.body.tierCode) || null

    const client = await dbPool.connect()
    try {
      await client.query("begin")

      let codeToUse = tierCode

      if (!codeToUse) {
        const currentSub = await getActiveSubscription(userId)
        if (!currentSub) {
          return res
            .status(400)
            .json({ error: "no_active_subscription" })
        }
        codeToUse = currentSub.tier_code
      }

      const tierResult = await client.query(
        "select * from subscription_tiers where code = $1",
        [codeToUse]
      )
      if (tierResult.rows.length === 0) {
        return res.status(400).json({ error: "unknown_tier" })
      }
      const tier = tierResult.rows[0]

      const currentSubResult = await client.query(
        `
          select *
          from subscriptions
          where user_id = $1
            and tier_code = $2
            and status = 'active'
          order by end_at desc
          limit 1
        `,
        [userId, codeToUse]
      )

      let startAt
      let endAt

      if (currentSubResult.rows.length === 0) {
        startAt = new Date()
        endAt = new Date(
          startAt.getTime() +
            tier.duration_days *
              24 *
              60 *
              60 *
              1000
        )
      } else {
        const current = currentSubResult.rows[0]
        startAt = current.start_at
        const baseEnd = current.end_at || new Date()
        const extraDays =
          Number.isFinite(days) && days > 0
            ? days
            : tier.duration_days
        endAt = new Date(
          baseEnd.getTime() +
            extraDays * 24 * 60 * 60 * 1000
        )
      }

      await client.query(
        "update subscriptions set status = 'expired' where user_id = $1 and status = 'active'",
        [userId]
      )

      const insert = await client.query(
        `
          insert into subscriptions (user_id, tier_code, status, start_at, end_at)
          values ($1,$2,'active',$3,$4)
          returning *
        `,
        [userId, codeToUse, startAt, endAt]
      )

      await client.query("commit")

      res.json({ subscription: insert.rows[0] })
    } catch (e) {
      await client.query("rollback")
      res.status(500).json({ error: "server_error" })
    } finally {
      client.release()
    }
  }
)

app.post("/api/paylych/webhook", async (req, res) => {
  const verification =
    req.query.verification ||
    req.headers["x-paylych-verification"] ||
    (req.body && req.body.verification)

  if (
    !process.env.PAYLYCH_VERIFICATION ||
    verification !== process.env.PAYLYCH_VERIFICATION
  ) {
    return res.status(403).json({ error: "forbidden" })
  }

  const status =
    (req.body && req.body.status) ||
    (req.body && req.body.operation) ||
    null

  if (
    !status ||
    !["success", "paid", "completed"].includes(
      String(status).toLowerCase()
    )
  ) {
    return res.json({ ok: true })
  }

  const email =
    (req.body && req.body.email) ||
    (req.body && req.body.customer_email) ||
    null

  const rawPlan =
    (req.body && req.body.plan_code) ||
    (req.body && req.body.tariff) ||
    (req.body && req.body.product_code) ||
    null

  if (!email || !rawPlan) {
    return res
      .status(400)
      .json({ error: "missing_email_or_plan" })
  }

  const planCode = String(rawPlan).toLowerCase()

  let normalizedPlan

  if (planCode.includes("trial")) {
    normalizedPlan = "trial"
  } else if (planCode.includes("day")) {
    normalizedPlan = "daily"
  } else if (
    planCode.includes("month") &&
    !planCode.includes("3") &&
    !planCode.includes("6") &&
    !planCode.includes("12")
  ) {
    normalizedPlan = "monthly"
  } else if (
    planCode.includes("3") &&
    planCode.includes("month")
  ) {
    normalizedPlan = "premium_3m"
  } else if (
    planCode.includes("6") &&
    planCode.includes("month")
  ) {
    normalizedPlan = "premium_6m"
  } else if (
    planCode.includes("12") &&
    planCode.includes("month")
  ) {
    normalizedPlan = "premium_12m"
  }

  if (!normalizedPlan) {
    return res.status(400).json({ error: "unknown_plan" })
  }

  try {
    let userResult = await dbPool.query(
      "select * from users where email = $1",
      [email]
    )

    let user

    if (userResult.rows.length === 0) {
      const isAdmin =
        process.env.ADMIN_EMAIL &&
        email.toLowerCase() ===
          process.env.ADMIN_EMAIL.toLowerCase()

      const insert = await dbPool.query(
        `
          insert into users (email, is_admin)
          values ($1,$2)
          returning *
        `,
        [email, isAdmin]
      )
      user = insert.rows[0]
    } else {
      user = userResult.rows[0]
    }

    await activateSubscription(user.id, normalizedPlan)

    res.json({ ok: true })
  } catch (e) {
    res.status(500).json({ error: "server_error" })
  }
})

app.get(
  `/${process.env.PAYLYCH_VERIFICATION || "shop-verification"}.txt`,
  (req, res) => {
    const token =
      process.env.PAYLYCH_VERIFICATION ||
      "shop-verification"
    res.type("text/plain").send(token)
  }
)

const staticDir = path.join(__dirname)
app.use(express.static(staticDir))

app.get("*", (req, res) => {
  res.sendFile(path.join(staticDir, "index.html"))
})

const port = Number(process.env.PORT || 3000)
app.listen(port, () => {
  console.log(`YTGO backend listening on port ${port}`)
})
