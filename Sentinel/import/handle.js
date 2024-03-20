/**
 * Creates a description in markdown for the alert based on the input properties.
 *
 * @param {Object} input - The input data from which to construct the alert description.
 * @returns {string} A string representing the constructed description for the alert.
 */
function createDescription(input) {
    let description = '';

    // Return early if input is null or undefined
    if (input === null || input === undefined) {
        return 'No description available';
    }
    // Return early if input object is missing properties
    else if (input.hasOwnProperty('object') === false && input.hasOwnProperty('properties') === false) {
        return 'No description available';
    }

    if (
        input.object.properties.hasOwnProperty('description') &&
        input.object.properties.description !== null &&
        input.object.properties.description !== ''
    ) {
        description += input.object.properties.description;
    }

    // Add alert information if available
    if (input.object.properties.hasOwnProperty('alerts')) {
        let alerts = input.object.properties.alerts;

        description += '\n\n';
        description += '### Related Alerts\n';
        description += `\n\n`;
        if (alerts.length > 0) {
            description += '| Alert Title | Alert ID | Start Time |\n';
            description += '| ----------- | -------- | ---------- |\n';

            alerts.forEach((alert) => {
                description += `| [${alert.properties.alertDisplayName}](${alert.properties.alertLink}) | ${alert.name} | ${alert.properties.startTimeUtc} |\n`;
            });
        } else {
            description += 'No related alerts found.';
        }
    }

    return description;
}

/**
 * Finds and returns patterns based on the techniques provided in the input.
 * This function queries a context object for each tactic's associated pattern.
 * It assumes the input object contains a list of techniques under `input.object.properties.additionalData.techniques`.
 * Each tactic is then used to query the context for matching patterns.
 *
 * @param {Object} input - The input object containing techniques under `additionalData.techniques`.
 * @param {Object} context - The context object providing a `query.execute` method to find patterns by tactic ID or name.
 * @returns {Array} An array of patterns associated with the given techniques. If no patterns are found, an empty array is returned.
 */
function findTactic(input, context) {
    const techniques = input.object.properties.additionalData.techniques;
    let patterns = [];
    if (techniques && techniques.length > 0) {
        techniques.forEach((t) => {
            // Execute a query to find a pattern by the tactic ID or name
            let lookup = context.query.execute([{ _name: 'getPattern', idOrName: t }]);
            // If the lookup finds one or more patterns, add them to the patterns array
            if (typeof lookup === 'object') {
                patterns.push(...lookup); // Fixed to push contents of lookup instead of the array itself
            }
        });
    }
    return patterns;
}

/**
 * Mapping of entity kinds to their respective observable data types, value properties, and optional tags.
 * This object defines how different kinds of entities (e.g., Mailbox, File) are mapped to observables
 * when processing security incidents. Each key represents an entity kind, and the associated value
 * defines the observable's data type, the property to extract the value from, and any relevant tags.
 */
const EntityToObservableMap = {
    Mailbox: { dataType: 'mail', valueProperty: 'mailboxPrimaryAddress', tags: ['mail-mailbox-primary-address'] },
    File: { dataType: 'filename', valueProperty: 'fileName' },
    FileHash: { dataType: 'hash', valueProperty: 'hashValue' },
    MailCluster: { dataType: 'other', valueProperty: 'networkMessageIds', tags: ['mail-network-message-id'] },
    MailMessage: [
        { dataType: 'mail-subject', valueProperty: 'subject' },
        { dataType: 'mail', valueProperty: 'recipient', tags: ['mail-recipient'] },
        { dataType: 'mail', valueProperty: 'recipient', tags: ['mail-recipient'] },
        { dataType: 'mail', valueProperty: 'p1Sender', tags: ['mail-sender'] },
        { dataType: 'domain', valueProperty: 'p1SenderDomain', tags: ['mail-sender-domain'] },
        { dataType: 'ip', valueProperty: 'senderIP', tags: ['mail-sender-ip'] },
        { dataType: 'mail', valueProperty: 'p2Sender', tags: ['mail-sender'] },
        { dataType: 'domain', valueProperty: 'p2SenderDomain', tags: ['mail-sender-domain'] },
        { dataType: 'ip', valueProperty: 'p2SenderIP', tags: ['mail-sender-ip'] },
        { dataType: 'other', valueProperty: 'internetMessageId', tags: ['mail-internet-message-id'] },
    ],
    Ip: { dataType: 'ip', valueProperty: 'address' },
};

/**
 * Creates an observable object with the given data type, data, and tags.
 *
 * @param {string} dataType - The type of data the observable represents.
 * @param {string} data - The actual data for the observable.
 * @param {Array<string>} [tags] - Optional tags associated with the observable.
 * @returns {Object|null} The observable object or null if the data is undefined or null.
 */
function createObservable(dataType, data, tags) {
    if (typeof data !== 'undefined' || data !== null) {
        let output = {
            dataType: dataType,
            data: data,
        };

        if (tags) {
            output.tags = tags;
        }
        return output;
    } else {
        return null;
    }
}

/**
 * Adds an observable to a list of observables, avoiding duplicates and merging tags if necessary.
 *
 * @param {string} dataType - The type of data the observable represents.
 * @param {string} data - The actual data for the observable.
 * @param {Array<string>} [tags] - Optional tags associated with the observable.
 * @param {Array<Object>} observables - The current list of observables to add to.
 */
function addObservable(dataType, data, tags, observables) {
    let existingObservable = observables.find(
        (observable) => observable.dataType === dataType && observable.data === data
    );
    if (existingObservable) {
        // If tags exist for the current observable, append new tags
        if (tags) {
            existingObservable.tags = Array.from(
                new Set(existingObservable.tags ? [...existingObservable.tags, ...tags] : [...tags])
            );
        }
    } else {
        let newObservable = createObservable(dataType, data, tags);
        if (newObservable) {
            observables.push(newObservable);
        }
    }
}

/**
 * Processes entities to extract observables based on the EntityToObservableMap configuration.
 *
 * @param {Array<Object>} input - The entities to process and extract observables from.
 * @returns {Array<Object>} A list of observables extracted from the given entities.
 */
function processObservables(input) {
    const entities = input.object.properties.relatedEntities;
    let observables = [];
    entities.forEach((entity) => {
        if (typeof EntityToObservableMap[entity.kind] !== 'undefined') {
            let entityMap = EntityToObservableMap[entity.kind];
            if (Array.isArray(entityMap)) {
                entityMap.forEach((map) => {
                    let dataValues = entity.properties[map.valueProperty];
                    if (Array.isArray(dataValues)) {
                        dataValues.forEach((value) => {
                            addObservable(map.dataType, value, map.tags, observables);
                        });
                    } else {
                        addObservable(map.dataType, dataValues, map.tags, observables);
                    }
                });
            } else {
                let dataValues = entity.properties[entityMap.valueProperty];
                if (Array.isArray(dataValues)) {
                    dataValues.forEach((value) => {
                        addObservable(entityMap.dataType, value, entityMap.tags, observables);
                    });
                } else {
                    addObservable(entityMap.dataType, dataValues, entityMap.tags, observables);
                }
            }
        }
    });

    // Remove duplicates and items with data value of undefined
    observables = observables.filter(
        (observable, index, self) =>
            index === self.findIndex((t) => t.dataType === observable.dataType && t.data === observable.data) &&
            observable.data !== undefined &&
            observable.data !== ''
    );

    return observables;
}

function processTechniques(input, context) {
    const tactics = findTactic(input, context);
    let patterns = [];
    if (tactics.length > 0) {
        tactics.forEach((tactic) => {
            patterns.push({
                patternId: tactic.patternId,
                tactic: tactic.tactics[0],
                occurDate: new Date(input.object.properties.createdTimeUtc).getTime(),
                description: tactic.description,
            });
        });
    }
    return patterns;
}

/**
 * Handles the incoming HTTP request, constructs an alert object, and invokes TheHive API to create the alert.
 *
 * @param {Object} input - The JSON payload passed when calling the script HTTP endpoint.
 * @param {Object} context - An object used to interact with TheHiveAPI.
 * @returns {Object} The result from creating the alert in TheHive.
 */
function handle(input, context) {
    const severityMap = {
        Informational: 1,
        Low: 1,
        Medium: 2,
        High: 3,
    };

    const theHiveAlert = {
        type: 'external',
        source: input.object.properties.providerName,
        sourceRef: input.object.properties.providerIncidentId,
        title: input.object.properties.title,
        description: '',
        severity: severityMap[input.object.properties.severity],
        status: 'New',
        date: new Date(input.object.properties.createdTimeUtc).getTime(),
        externalLink: input.object.properties.incidentUrl,
        observables: [],
    };

    let description = createDescription(input);
    theHiveAlert.description = description;
    theHiveAlert.observables = processObservables(input);

    if (input.object.properties.additionalData.techniques) {
        let tactics = findTactic(input, context);
        if (tactics.length > 0) {
            theHiveAlert.tags = [];
            tactics.forEach((t) => {
                theHiveAlert.tags.push(t.name);
            });
        }
        theHiveAlert.procedures = processTechniques(input, context);
    }

    const result = context.alert.create(theHiveAlert);
    return result;
}
