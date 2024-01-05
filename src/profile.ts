import { UserinfoResponse } from 'openid-client'

export function profileParser(user: UserinfoResponse) {
  const custom = user.custom as any[]

  const extractedData = custom.reduce((result, obj) => {
    for (const key in obj) {
      result[key] = obj[key]
    }
    return result
  }, {})

  const profile = {
    id: user.sub,
    userId: user.sub,
    ...extractedData,
  }

  return profile
}
