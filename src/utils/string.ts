export function getDomainFromOrigin(origin: string): string {
	// remove protocol with regex
	let newOrigin = origin.replace(/(^\w+:|^)\/\//, "");
	// remove port with regex
	return newOrigin.replace(/:\d+$/, "");
}
