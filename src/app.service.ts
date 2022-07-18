import { Injectable } from '@nestjs/common'
import axios from 'axios'
import { createHash } from 'crypto'
import * as jose from 'jose'

const BASE_URL = 'http://compliance.gaia-x.eu/api/v2204'
const TYPE_API_ATH = {
  ServiceOfferingExperimental: 'service-offering',
  LegalPerson: 'participant'
}

@Injectable()
export class AppService {
  async signSelfDescription(selfDescription: any): Promise<any> {
    const type = this.getSelfDescriptionType(selfDescription)
    selfDescription.credentialSubject[`gx-${type}:note`] = {
      '@value': 'Test Self Description signed by deltaDAO for the Gaia-X Hackathon #4',
      '@type': 'xsd:string'
    }

    const canonizedSD = await this.canonize(selfDescription)

    const hash = this.sha256(canonizedSD)
    this.logger(`📈 Hashed canonized SD ${hash}`)

    const proof = await this.createProof(hash)
    this.logger(proof ? '🔒 SD signed successfully (local)' : '❌ SD signing failed (local)')

    const verificationResult = await this.verify(proof.jws.replace('..', `.${hash}.`))
    this.logger(verificationResult?.content === hash ? '✅ Verification successful (local)' : '❌ Verification failed (local)')

    // the following code only works if you hosted your created did.json
    this.logger('🔍 Checking Self Description with the Compliance Service...')

    try {
      const complianceCredential = await this.signSd(selfDescription, proof)
      this.logger(complianceCredential ? '🔒 SD signed successfully (compliance service)' : '❌ SD signing failed (compliance service)')

      if (complianceCredential) {
        const completeSd = {
          selfDescriptionCredential: { ...selfDescription, proof },
          complianceCredential: complianceCredential.complianceCredential
        }

        const verificationResultRemote = await this.verifySelfDescription(completeSd)
        this.logger(
          verificationResultRemote?.conforms === true
            ? '✅ Verification successful (compliance service)'
            : `❌ Verification failed (compliance service): ${verificationResultRemote.conforms}`
        )

        return { signedSelfDescription: completeSd, result: verificationResultRemote }
      }
    } catch (error) {
      return error?.response?.data ? error?.response?.data : error
    }
  }

  async canonize(selfDescription: any): Promise<any> {
    const URL = BASE_URL + '/normalize'
    const { data } = await axios.post(URL, selfDescription)

    return data
  }

  sha256(input: string): string {
    return createHash('sha256').update(input).digest('hex')
  }

  async sign(hash: string): Promise<any> {
    const algorithm = 'PS256'
    const rsaPrivateKey = await jose.importPKCS8(process.env.PRIVATE_KEY, algorithm)

    const jws = await new jose.CompactSign(new TextEncoder().encode(hash))
      .setProtectedHeader({ alg: 'PS256', b64: false, crit: ['b64'] })
      .sign(rsaPrivateKey)

    return jws
  }

  private getCurrentTime(): string {
    return new Date().toISOString()
  }

  async createProof(hash: string): Promise<any> {
    const proof = {
      type: 'JsonWebKey2020',
      created: this.getCurrentTime(),
      proofPurpose: 'assertionMethod',
      verificationMethod: process.env.VERIFICATION_METHOD,
      jws: await this.sign(hash)
    }

    return proof
  }

  async verify(jws: any): Promise<any> {
    const algorithm = 'PS256'
    const x509 = await jose.importX509(process.env.CERTIFICATE, algorithm)
    const publicKeyJwk = await jose.exportJWK(x509)

    const pubkey = await jose.importJWK(publicKeyJwk, 'PS256')

    try {
      const result = await jose.compactVerify(jws, pubkey)

      return { protectedHeader: result.protectedHeader, content: new TextDecoder().decode(result.payload) }
    } catch (error) {
      return {}
    }
  }

  logger(...msg: Array<string>): void {
    if (process.env.NODE_ENV === 'production') return
    console.log(msg.join(' '))
  }

  async signSd(selfDescription: any, proof: any): Promise<any> {
    const URL = BASE_URL + '/sign'
    const { data } = await axios.post(URL, { ...selfDescription, proof })

    return data
  }

  private getSelfDescriptionType(selfDescription: any) {
    const credentialType = selfDescription['@type'].find(el => el !== 'VerifiableCredential')
    const type = TYPE_API_ATH[credentialType] || TYPE_API_ATH.LegalPerson

    return type
  }

  async verifySelfDescription(selfDescription: any): Promise<any> {
    const type = this.getSelfDescriptionType(selfDescription.selfDescriptionCredential)
    const URL = `${BASE_URL}/${type}/verify/raw`
    const { data } = await axios.post(URL, selfDescription)

    return data
  }
}
