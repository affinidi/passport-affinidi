import expressSesssion, { SessionOptions } from 'express-session'
import { generators } from 'openid-client'
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
  profileParser?: Function
  expressSesssion?: SessionOptions
  onSuccess?: Function
  onError?: Function
  routes?: {
    init?: string
    initHandler?: Function
    complete?: string
    completeHandler?: Function
  }
}

export const affinidiProvider = async (app: any, options: ProviderOptionsType) => {
  const { client, strategy, sessionKey } = await AffinidiStrategy(options)

  passport.use('affinidi-oidc', strategy)

  // app.use(passport.initialize());
  // app.use(passport.session());

  app.use(
    expressSesssion({
      secret: options.id,
      resave: false,
      saveUninitialized: true,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 1000 * 60 * 60 * 24 * 1, // 1 day
      },
      unset: 'destroy',
      ...options.expressSesssion,
    }),
  )

  // handles serialization and deserialization of authenticated user
  // passport.serializeUser(function (user, done) {
  //     done(null, user);
  // });
  // passport.deserializeUser(function (user, done) {
  //     done(null, user);
  // });

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
    passport.authenticate('affinidi-oidc', {}, function (err: any, user: any, info: any) {
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

  app.get(options.routes?.init || '/api/affinidi-auth/init', options.routes?.initHandler || initHandler)

  app.post(
    options.routes?.complete || '/api/affinidi-auth/complete',
    options.routes?.completeHandler || completeHandler,
  )
}
