export type Accountability = {
	role: string | null;
	user?: string | null;
	admin?: boolean;
	app?: boolean;
	scope?: string | null;
	ip?: string;
	userAgent?: string;
};
