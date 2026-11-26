import type { ReactNode } from "react";

interface PanelProps {
  id: string;
  title: string;
  stage?: string; // the pipeline stage this panel shows, e.g. "Detect"
  aside?: ReactNode;
  className?: string;
  children: ReactNode;
}

export function Panel({ id, title, stage, aside, className, children }: PanelProps) {
  const headingId = `${id}-title`;
  return (
    <section className={`panel ${className ?? ""}`} aria-labelledby={headingId}>
      <header className="panel__header">
        <h2 id={headingId} className="panel__title">
          {stage ? <span className="panel__stage">{stage}</span> : null}
          {title}
        </h2>
        {aside ? <div className="panel__aside">{aside}</div> : null}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}
