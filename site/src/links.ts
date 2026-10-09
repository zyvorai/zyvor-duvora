export const REPO = 'https://github.com/zyvorai/duvora';
const utm = (c: string) => `utm_source=github&utm_medium=duvora&utm_campaign=${c}`;

export const links = {
  repo: REPO,
  demo: `https://zyvor.dev/schedule?${utm('site_hero')}`,
  poc: `https://zyvor.dev/poc?${utm('site_hero')}`,
  pricing: `https://zyvor.dev/pricing?${utm('site_footer')}`,
  sales: 'mailto:sales@zyvor.dev?subject=Duvora',
};
