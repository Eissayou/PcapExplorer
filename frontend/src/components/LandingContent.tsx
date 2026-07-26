import React, { useEffect } from 'react';
import { AUTHOR, FAQS, FEATURES, STEPS } from '../content';
import { ChevronDownIcon } from './Icons';

/**
 * Publishes the FAQPage schema built from the same FAQ array the page renders.
 *
 * The tag is added to <head> on mount and removed on unmount, so it is only
 * present while the questions it describes are actually on screen. Structured
 * data has to match visible content.
 */
const FaqSchema: React.FC = () => {
    useEffect(() => {
        const script = document.createElement('script');
        script.type = 'application/ld+json';
        script.textContent = JSON.stringify({
            '@context': 'https://schema.org',
            '@type': 'FAQPage',
            mainEntity: FAQS.map((faq) => ({
                '@type': 'Question',
                name: faq.question,
                acceptedAnswer: { '@type': 'Answer', text: faq.answer },
            })),
        });
        document.head.appendChild(script);
        return () => script.remove();
    }, []);
    return null;
};

const SectionHeading: React.FC<{ id: string; eyebrow: string; title: string; children?: React.ReactNode }> = ({
    id,
    eyebrow,
    title,
    children,
}) => (
    <div className="max-w-2xl">
        <p className="text-xs font-semibold uppercase tracking-widest text-indigo-600">{eyebrow}</p>
        <h2 id={id} className="mt-2 text-2xl sm:text-3xl font-bold text-slate-900">
            {title}
        </h2>
        {children && <p className="mt-3 text-slate-600">{children}</p>}
    </div>
);

const Card: React.FC<{ title: string; body: string; badge?: React.ReactNode }> = ({ title, body, badge }) => (
    <div className="rounded-xl border border-slate-200/80 bg-white p-6 shadow-sm">
        {badge}
        <h3 className={`font-semibold text-slate-900 ${badge ? 'mt-4' : ''}`}>{title}</h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-600">{body}</p>
    </div>
);

const link = 'font-medium text-indigo-600 hover:text-indigo-700';
const button = 'inline-flex items-center gap-2 rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 transition';

export const LandingContent: React.FC = () => (
    <div className="mt-20 space-y-20">
        <FaqSchema />

        <section aria-labelledby="how-it-works">
            <SectionHeading id="how-it-works" eyebrow="How it works" title="Three steps from capture to map">
                PCAP Explorer parses your capture server-side in Go with{' '}
                <a className={link} href="https://github.com/google/gopacket" target="_blank" rel="noopener">
                    gopacket
                </a>
                , then draws the result as charts and an interactive map.
            </SectionHeading>
            <ol className="mt-8 grid gap-6 md:grid-cols-3">
                {STEPS.map((step, i) => (
                    <li key={step.title}>
                        <Card
                            title={step.title}
                            body={step.body}
                            badge={<span className="grid h-9 w-9 place-items-center rounded-lg bg-indigo-600 text-sm font-bold text-white">{i + 1}</span>}
                        />
                    </li>
                ))}
            </ol>
        </section>

        <section aria-labelledby="features">
            <SectionHeading id="features" eyebrow="What you get" title="The shape of a capture, without the packet list">
                Wireshark is what you want when the question is about one packet. This is for when the question is about the whole file.
            </SectionHeading>
            <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                {FEATURES.map((feature) => (
                    <Card key={feature.title} title={feature.title} body={feature.body} />
                ))}
            </div>
        </section>

        <section aria-labelledby="faq">
            <SectionHeading id="faq" eyebrow="FAQ" title="Questions about PCAP files, answered" />
            <div className="mt-8 grid gap-4 lg:grid-cols-2">
                {FAQS.map((faq) => (
                    <details
                        key={faq.question}
                        className="group rounded-xl border border-slate-200/80 bg-white p-5 shadow-sm open:shadow-md transition-shadow"
                    >
                        <summary className="flex cursor-pointer items-center justify-between gap-4 font-semibold text-slate-900 marker:content-none">
                            <h3 className="text-base">{faq.question}</h3>
                            <ChevronDownIcon className="h-5 w-5 shrink-0 text-slate-400 transition-transform group-open:rotate-180" />
                        </summary>
                        <p className="mt-3 text-sm leading-relaxed text-slate-600">{faq.answer}</p>
                    </details>
                ))}
            </div>
        </section>

        <section aria-labelledby="author" className="rounded-2xl border border-slate-200/80 bg-white p-6 sm:p-10 shadow-sm">
            <div className="flex flex-col gap-6 sm:flex-row sm:items-start">
                <img
                    src="/je.png"
                    alt="Jason Eissayou"
                    width={80}
                    height={80}
                    loading="lazy"
                    className="h-20 w-20 shrink-0 rounded-2xl object-cover ring-1 ring-slate-200"
                />
                <div>
                    <p className="text-xs font-semibold uppercase tracking-widest text-indigo-600">Who built this</p>
                    <h2 id="author" className="mt-2 text-2xl font-bold text-slate-900">
                        <a href={AUTHOR.site} rel="author noopener" target="_blank" className="hover:text-indigo-700">
                            {AUTHOR.name}
                        </a>
                    </h2>
                    <p className="mt-1 text-sm font-medium text-slate-500">Software Developer, Cloud Security and AI</p>
                    <p className="mt-4 max-w-2xl leading-relaxed text-slate-600">
                        I&rsquo;m Jason Eissayou, a software developer working in cloud security and AI, with an MS in Computer Science and an
                        incoming software developer role at IBM. I built PCAP Explorer because I kept opening Wireshark just to answer one
                        question, <em>who is this machine actually talking to?</em>, and I wanted that answer without scrolling a packet list.
                        The backend is Go with gopacket, the frontend is React and TypeScript, and the whole thing runs as one container on
                        Azure.
                    </p>
                    <p className="mt-4 max-w-2xl leading-relaxed text-slate-600">
                        I write up the engineering behind my projects on my site, including this one, an{' '}
                        <a className={link} href="https://www.eissayou.com/projects/azure-honeypot.html" target="_blank" rel="noopener">
                            Azure honeypot threat map
                        </a>{' '}
                        built on Sentinel and Terraform, and{' '}
                        <a className={link} href="https://www.eissayou.com/projects/formfixai.html" target="_blank" rel="noopener">
                            FormFixAI
                        </a>
                        , an AI workout-form analyzer.
                    </p>
                    <div className="mt-6 flex flex-wrap gap-3">
                        <a
                            href={AUTHOR.site}
                            rel="author noopener"
                            target="_blank"
                            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 transition"
                        >
                            eissayou.com
                        </a>
                        <a href={AUTHOR.caseStudy} target="_blank" rel="noopener" className={button}>
                            Read the case study
                        </a>
                        <a href={AUTHOR.repo} target="_blank" rel="noopener" className={button}>
                            Source on GitHub
                        </a>
                    </div>
                </div>
            </div>
        </section>
    </div>
);
