import Hero from './sections/Hero';
import Stats from './sections/Stats';
import Features from './sections/Features';
import RuleDemo from './sections/RuleDemo';
import Compare from './sections/Compare';
import Gallery from './sections/Gallery';
import Quickstart from './sections/Quickstart';
import Cta from './sections/Cta';
import { REPO } from './links';


export default function App() {
  return (
    <>
      <nav className="nav">
        <a className="brand" href="#top">Duvora</a>
        <div className="nav-links">
          <a href="#features">Features</a>
          <a href="#try">Try it</a>
          <a href="#compare">vs DPF</a>
          <a href="#start">Quickstart</a>
          <a className="btn btn-sm" href={REPO}>GitHub</a>
        </div>
      </nav>
      <main id="top">
        <Hero />
        <Stats />
        <Features />
        <RuleDemo />
        <Compare />
        <Gallery />
        <Quickstart />
        <Cta />
      </main>
      <footer className="foot">
        Apache-2.0 · <a href={REPO}>GitHub</a> · <a href="https://zyvor.dev">zyvor.dev</a> · A Zyvor AI Labs project. Duvora 0.5.0 is a runnable evaluation release; see the <a href={`${REPO}/blob/main/docs/STATUS.md`}>capability matrix</a>.
      </footer>
    </>
  );
}
