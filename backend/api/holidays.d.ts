import { Router } from 'express';

declare module './api/holidays' {
	const router: Router;
	export default router;
}
