import { useLayoutEffect, type RefObject } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { chapters } from "./story";
import { keyStarts, VAULT } from "./VaultStage";

gsap.registerPlugin(ScrollTrigger);

const { KEYHOLE, C } = VAULT;

/**
 * One master timeline, 100 units long, so positions read as "percent of the story".
 * It is scrubbed by scroll while the section is pinned.
 */
export function useVaultTimeline(root: RefObject<HTMLElement>, enabled: boolean, onChapter: (i: number) => void) {
  useLayoutEffect(() => {
    if (!enabled || !root.current) return;

    const ctx = gsap.context(() => {
      const q = gsap.utils.selector(root);
      const keys = q(".v-key");

      // ---- initial (vulnerable) state ----
      gsap.set(".v-bolt", { x: -62 });
      gsap.set(".v-cap", { autoAlpha: 0, y: 28 });
      gsap.set(".v-cap-0", { autoAlpha: 1, y: 0 });
      gsap.set(".v-hub-light", { attr: { fill: "#fb7185" } });
      gsap.set(".v-pick", { x: 320 });
      gsap.set(".v-crowbar", { x: 260 });
      gsap.set(".v-sparks", { scale: 0, transformOrigin: "50% 50%" });
      gsap.set(".v-goodkey", { y: 180 });
      gsap.set(".v-visitor", { x: 140 });
      gsap.set(".v-alert", { y: 40 });
      gsap.set(".v-bar", { scaleX: 0 });
      gsap.set([".v-rule1", ".v-rule2", ".v-label1", ".v-label2", ".v-counter"], { y: -8 });
      keys.forEach((el, i) => gsap.set(el, { x: keyStarts[i].sx, y: keyStarts[i].sy, rotation: keyStarts[i].rot, transformOrigin: "50% 50%" }));

      const counter = { n: 0 };
      const countEl = q(".v-count")[0];
      const throttledEl = q(".v-throttled")[0];
      const renderCount = () => {
        const n = Math.round(counter.n);
        if (countEl) countEl.textContent = n.toLocaleString("en");
        if (throttledEl) throttledEl.textContent = Math.max(0, n - 16).toLocaleString("en");
      };

      const tl = gsap.timeline({
        defaults: { ease: "power2.inOut", duration: 3 },
        scrollTrigger: {
          trigger: root.current,
          start: "top top",
          end: "+=650%",
          pin: true,
          scrub: 0.6,
          anticipatePin: 1,
          onUpdate: (self) => {
            const p = self.progress * 100;
            let idx = 0;
            chapters.forEach((c, i) => {
              if (p >= c.at) idx = i;
            });
            onChapter(idx);
          },
        },
      });

      const capSwap = (from: number, to: number, at: number) => {
        tl.to(`.v-cap-${from}`, { autoAlpha: 0, y: -28, duration: 2.5 }, at);
        tl.to(`.v-cap-${to}`, { autoAlpha: 1, y: 0, duration: 2.5 }, at + 1.5);
      };

      // ---- 0–8 hero: the vault wakes up ----
      tl.to(".v-rim", { opacity: 1, duration: 6 }, 0);
      tl.to(".v-scrollcue", { autoAlpha: 0, duration: 2 }, 1);

      // ---- 8–28 scan ----
      capSwap(0, 1, 7);
      tl.to(".v-pick", { opacity: 1, x: 0, duration: 4, ease: "power3.out" }, 9);
      tl.to(".v-pick", { rotation: 4, duration: 0.8, yoyo: true, repeat: 3, ease: "sine.inOut" }, 13);
      tl.to(".v-scangrid", { opacity: 1, duration: 2 }, 13);
      tl.to(".v-beam", { opacity: 1, duration: 1 }, 13);
      tl.fromTo(".v-beam", { x: 60 }, { x: 680, duration: 9, ease: "none" }, 13);
      tl.to(".v-weak1", { opacity: 1, duration: 1 }, 15.5);
      tl.to(".v-label1", { opacity: 1, y: 0, duration: 1 }, 15.5);
      tl.to(".v-weak2", { opacity: 1, duration: 1 }, 18.5);
      tl.to(".v-label2", { opacity: 1, y: 0, duration: 1 }, 18.5);
      tl.to([".v-beam", ".v-scangrid"], { opacity: 0, duration: 2 }, 23);

      // ---- 28–48 protect ----
      capSwap(1, 2, 27);
      tl.to(".v-crowbar", { opacity: 1, x: 40, duration: 3, ease: "power3.out" }, 29);
      tl.to(".v-crowbar", { x: 0, duration: 0.8, ease: "power4.in" }, 32);
      tl.to(".v-sparks", { opacity: 1, scale: 1.2, duration: 0.8, ease: "power2.out" }, 32.6);
      tl.to(".v-sparks", { opacity: 0, scale: 1.6, duration: 1.2 }, 33.4);
      tl.to(".v-rule1", { opacity: 1, y: 0, duration: 1.5, ease: "back.out(2)" }, 34);
      tl.to(".v-rule2", { opacity: 1, y: 0, duration: 1.5, ease: "back.out(2)" }, 35);
      tl.to(".v-bolt", { x: 0, duration: 3, stagger: 0.15, ease: "power3.inOut" }, 35.5);
      tl.to(".v-hub-light", { attr: { fill: "#2dd4bf" }, duration: 1 }, 38);
      tl.to(".v-door-rim", { opacity: 0.8, duration: 2 }, 38);
      tl.to([".v-weak1", ".v-weak2", ".v-label1", ".v-label2"], { opacity: 0, duration: 1.5 }, 39);
      tl.to([".v-fixed1", ".v-fixed2"], { opacity: 1, duration: 1.5 }, 39.5);
      // the pick snaps and falls
      tl.to(".v-pick", { x: 40, y: 120, rotation: 70, opacity: 0, duration: 3, ease: "power2.in" }, 40);
      tl.to(".v-crowbar", { x: 200, y: 160, rotation: -30, opacity: 0, duration: 3, ease: "power2.in" }, 41);
      tl.to([".v-fixed1", ".v-fixed2", ".v-door-rim"], { opacity: 0, duration: 2 }, 45);

      // ---- 48–64 flood ----
      capSwap(2, 3, 47);
      tl.to(".v-rule1", { opacity: 0.35, duration: 1 }, 48);
      tl.to(".v-counter", { opacity: 1, y: 0, duration: 1.5 }, 49);
      tl.to(keys, { opacity: 1, duration: 0.6, stagger: 0.2 }, 49);
      tl.to(
        keys,
        { x: KEYHOLE.x - 30, y: KEYHOLE.y - 8, rotation: 0, duration: 2.4, stagger: 0.2, ease: "power2.in" },
        49.2,
      );
      tl.to(
        keys,
        {
          x: (i) => keyStarts[i].ex,
          y: (i) => keyStarts[i].ey,
          rotation: (i) => keyStarts[i].rot * 0.6,
          color: "#64748b",
          opacity: 0.25,
          duration: 2.4,
          stagger: 0.2,
          ease: "power2.out",
        },
        51.6,
      );
      tl.to(counter, { n: 1204, duration: 9, ease: "none", onUpdate: renderCount }, 50);
      tl.to(keys, { opacity: 0, duration: 1.5 }, 62);
      tl.to([".v-counter", ".v-rule1", ".v-rule2"], { opacity: 0, duration: 1.5 }, 62);

      // ---- 64–82 learn ----
      capSwap(3, 4, 63);
      tl.to(".v-visitor", { opacity: 1, x: 0, duration: 4, ease: "power3.out" }, 65);
      tl.to(".v-odd", { opacity: 1, duration: 1.5 }, 69.5);
      tl.to(".v-hub-light", { attr: { fill: "#fb7185" }, duration: 0.6, repeat: 3, yoyo: true }, 70);
      tl.to(".v-alert", { opacity: 1, y: 0, duration: 2.5, ease: "power3.out" }, 71);
      tl.to(".v-bar", { scaleX: 1, duration: 3, stagger: 0.5, ease: "power2.out" }, 72.5);
      tl.to([".v-alert", ".v-visitor"], { opacity: 0, duration: 2 }, 80);

      // ---- 82–100 the right key; the door opens ----
      capSwap(4, 5, 82);
      tl.to(".v-goodkey", { opacity: 1, y: 0, duration: 3, ease: "power3.out" }, 83);
      tl.to(".v-goodkey", { rotation: 90, svgOrigin: `${KEYHOLE.x} ${KEYHOLE.y}`, duration: 1.5 }, 86);
      tl.to(".v-hub-light", { attr: { fill: "#5eead4" }, duration: 0.5 }, 87);
      tl.to(".v-wheel", { rotation: 300, svgOrigin: `${C} ${C}`, duration: 4, ease: "power2.inOut" }, 87.5);
      tl.to(".v-bolt", { x: -62, duration: 2.5, stagger: 0.08 }, 88.5);
      tl.to(".v-goodkey", { opacity: 0, duration: 1 }, 90);
      tl.to(".v-light", { opacity: 0.35, duration: 2 }, 90.5);
      tl.to(".v-door", { rotationY: -108, transformOrigin: "16.5% 50%", duration: 6, ease: "power2.inOut" }, 91.5);
      tl.to(".v-light", { opacity: 1, duration: 4 }, 92);
      // fade the swinging door before it crosses the caption column
      tl.to(".v-door", { opacity: 0, duration: 2.5, ease: "power1.in" }, 93);
      tl.to(".v-stage", { scale: 1.25, duration: 6, ease: "power1.in" }, 94);
      tl.to(".v-chapters", { autoAlpha: 0, duration: 2 }, 97);
      tl.set({}, {}, 100);
    }, root);

    return () => ctx.revert();
  }, [enabled, root, onChapter]);
}
