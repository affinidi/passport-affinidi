import expressSesssion, { SessionOptions } from 'express-session'
import { TokenSet, generators } from 'openid-client'
import passport from 'passport'

import { profileParser } from './profile'
import AffinidiStrategy from './strategy'

export type ProviderOptionsType = {
  id: string
  issuer: string
  client_id: string
  client_secret: string
  redirect_uris: string[]
  verifyCallback?: any
  expressSesssion?: SessionOptions
  onSuccess?: Function
  onError?: Function
  noSPARoutes?: Boolean
  passport?: {
    initializeSession?: Boolean
    serializeUser?: any
    deserializeUser?: any
  }
  profileParser?: Function
  routes?: {
    init?: string
    initHandler?: Function
    complete?: string
    completeHandler?: Function
  }
}

export const affinidiPassport = passport

export const affinidiProvider = async (app: any, options: ProviderOptionsType) => {
  //setting default
  options = {
    verifyCallback: (req: any, tokenSet: TokenSet, userinfo: unknown, done: Function) => {
      return done(null, tokenSet.claims())
    },
    profileParser,
    noSPARoutes: false,
    passport: {
      initializeSession: false,
    },
    ...options,
  }
  const { client, strategy, sessionKey } = await AffinidiStrategy(options)

  passport.use(options.id, strategy)

  app.use(
    expressSesssion(
      options.expressSesssion || {
        secret: options.id,
        resave: false,
        saveUninitialized: true,
        cookie: {
          secure: process.env.NODE_ENV === 'production',
          maxAge: 1000 * 60 * 60 * 24 * 1, // 1 day
        },
        unset: 'destroy',
      },
    ),
  )

  if (options.passport?.initializeSession === true) {
    app.use(passport.initialize())
    app.use(passport.session())

    //handles serialization and deserialization of authenticated user
    passport.serializeUser(
      options.passport?.serializeUser ||
        function (user: any, done) {
          done(null, user)
        },
    )

    passport.deserializeUser(
      options.passport?.deserializeUser ||
        function (user: any, done) {
          done(null, user)
        },
    )
  }

  const initHandler = (req: any, res: any, next: any) => {
    const code_verifier = generators.codeVerifier()
    const params = {
      code_challenge: generators.codeChallenge(code_verifier),
      code_challenge_method: 'S256',
      response_type: 'code',
      scope: 'openid',
      state: generators.state(),
    }
    req.session[sessionKey] = {
      state: params.state,
      response_type: params.response_type,
      code_verifier,
    }

    const authorizationUrl = client.authorizationUrl(params)
    res.send({ authorizationUrl })
  }

  const completeHandler = (req: any, res: any, next: any) => {
    passport.authenticate(options.id, {}, function (err: any, user: any, info: any) {
      if (err) {
        if (options.onError && typeof options.onError === 'function') {
          options.onError(err, info)
        }
        res.status(400).send({
          error: err.message,
          error_description: err.error_description,
        })
      } else {
        const profile = (options.profileParser && options.profileParser(user)) || profileParser(user)
        if (options.onSuccess && typeof options.onSuccess === 'function') {
          options.onSuccess(user, profile, info)
        }
        res.send({ user: profile })
      }
    })(req, res, next)
  }

  if (options.noSPARoutes !== true) {
    app.get(options.routes?.init || '/api/affinidi-auth/init', options.routes?.initHandler || initHandler)

    app.post(
      options.routes?.complete || '/api/affinidi-auth/complete',
      options.routes?.completeHandler || completeHandler,
    )
  }
}
