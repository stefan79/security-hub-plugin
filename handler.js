'use strict'

// const gremlin = require('gremlin')
const Promise = require('bluebird')
const R = require('ramda')
const { config, SecurityHub } = require('aws-sdk')

config.setPromisesDependency(Promise)

const createFinding = R.applySpec({
  id: R.prop('Id'),
  resources: R.pipe(R.prop('Resources'), R.map(R.prop('Id'))),
  label: R.prop('Title'),
  description: R.prop('Description'),
  remedy: R.path(['Remidiation', 'Recomendation']),
  status: R.path(['Compliance', ['Status']]),
  rule: {
    id: R.path(['ProductFields', 'StanardsArn']),
    control: R.path(['ProductFields', 'ControlId']),
    severity: R.path(['Severity', 'Normalized'])
  },
  plugin: R.always('security-hub')
})

module.exports.updateFindings = async (event) => {
  const hub = new SecurityHub()
  const filter = { Filters: { RecordState: [{ Comparison: 'EQUALS', Value: 'ACTIVE' }] } }
  let findings = await hub.getFindings(filter).promise()
  let hasMore = true
  const collection = []
  while (hasMore) {
    collection.push(R.pipe(R.prop('Findings'), R.map(createFinding))(findings))
    if (findings.NextToken) {
      findings = await hub.getFindings({ ...filter, NextToken: findings.NextToken }).promise()
    } else {
      hasMore = false
    }
  }

  /*
    {resource-id: arn,
    finding-id: id,
    label: text
    debug: JSON
    }
  */

  function onlyUnique (value, index, self) {
    return self.indexOf(value) === index
  }

  return collection.flat().map(finding => ({
    'resource-id': finding.resources[0],
    'finding-id': finding.id,
    label: finding.label,
    description: finding.description,
    status: finding.status,
    debug: JSON.stringify(finding)
  }))
  // return collection.flat().map(x => x.resources).flat().filter(onlyUnique).sort()
}
