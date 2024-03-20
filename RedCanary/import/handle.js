// Your script should have a function named 'handle'
// input is the json value that is passed when calling the script http endpoint
// context is an object used to interact with TheHiveAPI
function handle(input, context) {
    const theHiveAlert = {
        type: 'event',
        source: 'RedCanary',
        sourceRef: input.Detection.id,
        title: input.Detection.headline,
        description: input.Detection.details,
        date: new Date(input.Detection.published_at).getTime(),
        observables: [],
    };

    if (input.Endpoint) {
        if (Array.isArray(input.Endpoint)) {
            input.Endpoint.forEach((o) =>
                theHiveAlert.observables.push({
                    dataType: 'hostname',
                    data: [o.hostname],
                })
            );
        } else {
            theHiveAlert.observables.push({
                dataType: 'hostname',
                data: [input.Endpoint.hostname],
            });
        }
    }

    if (input.EndpointUser) {
        if (Array.isArray(input.EndpointUser)) {
            input.Endpoint.forEach((o) => theHiveAlert.observables.push({ dataType: 'mail', data: [o.username] }));
        } else {
            theHiveAlert.observables.push({
                dataType: 'mail',
                data: [input.EndpointUser.username],
            });
        }
    }

    // call TheHive APIs, here alert creation
    return context.alert.create(theHiveAlert);
    //return theHiveAlert
}
