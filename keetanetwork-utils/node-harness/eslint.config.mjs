import keetanetworkConfig from '@keetanetwork/eslint-config-typescript';

export default [
	{
		ignores: ['**/*', '!src/**']
	},
	...keetanetworkConfig,
	{
		languageOptions: {
			parserOptions: {
				project: ['tsconfig.json']
			}
		}
	}
];
