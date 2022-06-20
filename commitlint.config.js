/* eslint-disable @typescript-eslint/no-var-requires */
const conventional = require('@commitlint/config-conventional')

const { rules } = conventional
const types = rules['type-enum'][2]

module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', types.concat(['deps', 'merge'])]
  }
}
