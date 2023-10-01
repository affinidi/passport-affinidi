import { Issuer, Strategy, TokenSet } from 'openid-client'
import { ProviderOptionsType } from '.'

export default async function AffinidiStrategy(options: ProviderOptionsType) {
  if (typeof options.issuer !== 'string' || !options.issuer) {
    throw new TypeError('affinidi issuer is required')
  }
  if (typeof options.client_id !== 'string' || !options.client_id) {
    throw new TypeError('affinidi client_id is required')
  }
  if (typeof options.client_secret !== 'string' || !options.client_secret) {
    throw new TypeError('affinidi client_secret is required')
  }

  //discover the wellknown for issuer
  const affinidi = await Issuer.discover(options.issuer)
  //console.log('Discovered issuer %s %O', affinidi.issuer, affinidi.metadata)
  const sessionKey = `oidc:${options.id || 'affinidi'}-session-key`

  var client = new affinidi.Client({
    client_id: options.client_id,
    client_secret: options.client_secret,
    redirect_uris: options.redirect_uris,
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  })

  const defaultVerifyCallback = (tokenSet: TokenSet, userinfo: unknown, done: Function) => {
    return done(null, tokenSet.claims())
  }

  return {
    client,
    sessionKey,
    strategy: new Strategy({ client, sessionKey }, options.verifyCallback || defaultVerifyCallback),
  }
}
