import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { useApp } from '../store';

interface Forensic3DCoreProps {
  size?: number;
  className?: string;
  interactive?: boolean;
}

/**
 * Forensic3DCore
 * A subtle, elegant, interactive 3D cryptographic core / cyber-polyhedron
 * built with Three.js. Spins slowly, tracks mouse cursor parallax,
 * and bursts with a high-speed spin and flare when clicked!
 */
export const Forensic3DCore: React.FC<Forensic3DCoreProps> = ({
  size = 48,
  className = '',
  interactive = true
}) => {
  const { theme } = useApp();
  const isLight = theme === 'light';
  const mountRef = useRef<HTMLDivElement>(null);
  const clickBurstRef = useRef<number>(0);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({
        alpha: true,
        antialias: true,
        powerPreference: 'low-power'
      });
    } catch {
      return;
    }

    renderer.setSize(size, size);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x000000, 0);
    container.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, 1, 0.1, 100);
    camera.position.z = 3.6;

    // Ambient & Point light with warm cyber-orange tint
    const ambientLight = new THREE.AmbientLight(0xffedd5, 0.9);
    scene.add(ambientLight);

    const pointLight = new THREE.PointLight(0xf95721, 2.5, 10);
    pointLight.position.set(2, 2, 3);
    scene.add(pointLight);

    const backLight = new THREE.PointLight(0xea580c, 1.8, 10);
    backLight.position.set(-2, -2, -2);
    scene.add(backLight);

    // Root Group
    const group = new THREE.Group();
    scene.add(group);

    // Outer Geodesic / Icosahedron Wireframe
    const outerGeo = new THREE.IcosahedronGeometry(1.0, 1);
    const wireframeGeo = new THREE.WireframeGeometry(outerGeo);
    const wireframeMat = new THREE.LineBasicMaterial({
      color: isLight ? 0xc2410c : 0xf95721,
      transparent: true,
      opacity: isLight ? 0.9 : 0.85,
      linewidth: 1
    });
    const wireframeMesh = new THREE.LineSegments(wireframeGeo, wireframeMat);
    group.add(wireframeMesh);

    // Inner Faceted Core with warm obsidian & ember reflection
    const innerGeo = new THREE.OctahedronGeometry(0.62, 0);
    const innerMat = new THREE.MeshStandardMaterial({
      color: isLight ? 0x29140d : 0x1f120c,
      roughness: 0.25,
      metalness: 0.9,
      emissive: isLight ? 0xc2410c : 0xea580c,
      emissiveIntensity: isLight ? 0.45 : 0.35,
      flatShading: true
    });
    const innerMesh = new THREE.Mesh(innerGeo, innerMat);
    group.add(innerMesh);

    // Orbiting Cyber Ring
    const ringGeo = new THREE.TorusGeometry(1.25, 0.02, 8, 32);
    const ringMat = new THREE.MeshBasicMaterial({
      color: isLight ? 0xea580c : 0xfb923c,
      transparent: true,
      opacity: isLight ? 0.65 : 0.5
    });
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 3;
    group.add(ringMesh);

    // Subtle floating vertex beacon particles
    const particleCount = 12;
    const particlePositions = new Float32Array(particleCount * 3);
    for (let i = 0; i < particleCount; i++) {
      const theta = (i / particleCount) * Math.PI * 2;
      particlePositions[i * 3] = Math.cos(theta) * 1.25;
      particlePositions[i * 3 + 1] = Math.sin(theta) * 0.4;
      particlePositions[i * 3 + 2] = Math.sin(theta) * 1.25;
    }
    const particleGeo = new THREE.BufferGeometry();
    particleGeo.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3));
    const particleMat = new THREE.PointsMaterial({
      color: 0xffedd5,
      size: 0.08,
      transparent: true,
      opacity: 0.8
    });
    const particleCloud = new THREE.Points(particleGeo, particleMat);
    group.add(particleCloud);

    // Mouse tracking for tilt
    let mouseX = 0;
    let mouseY = 0;
    let targetRotX = 0;
    let targetRotY = 0;
    let isHovered = false;

    const onPointerMove = (e: MouseEvent) => {
      if (!interactive) return;
      const rect = container.getBoundingClientRect();
      const x = (e.clientX - (rect.left + rect.width / 2)) / (rect.width / 2);
      const y = (e.clientY - (rect.top + rect.height / 2)) / (rect.height / 2);
      targetRotX = y * 0.8;
      targetRotY = x * 0.8;
    };

    const onMouseEnter = () => {
      isHovered = true;
    };

    const onMouseLeave = () => {
      isHovered = false;
      targetRotX = 0;
      targetRotY = 0;
    };

    const onClick = () => {
      clickBurstRef.current = 1.0;
    };

    if (interactive) {
      container.addEventListener('mousemove', onPointerMove);
      container.addEventListener('mouseenter', onMouseEnter);
      container.addEventListener('mouseleave', onMouseLeave);
      container.addEventListener('click', onClick);
    }

    let animId: number;
    let baseTime = 0;

    const animate = () => {
      animId = requestAnimationFrame(animate);
      baseTime += 0.015;

      // Burst velocity decay
      let burstSpeed = 0;
      if (clickBurstRef.current > 0.005) {
        burstSpeed = clickBurstRef.current * 0.25;
        clickBurstRef.current *= 0.94;
      }

      const idleSpeed = isHovered ? 0.035 : 0.015;
      group.rotation.y += idleSpeed + burstSpeed;
      group.rotation.x += (idleSpeed * 0.5) + (burstSpeed * 0.5);

      // Mouse Parallax interpolation
      mouseX += (targetRotX - mouseX) * 0.1;
      mouseY += (targetRotY - mouseY) * 0.1;
      camera.position.x = mouseY * 0.5;
      camera.position.y = -mouseX * 0.5;
      camera.lookAt(0, 0, 0);

      // Counter-rotate inner core & ring for dynamic aesthetic
      innerMesh.rotation.y -= 0.02 + burstSpeed;
      ringMesh.rotation.z += 0.01 + burstSpeed * 0.5;

      // Pulse glow on wireframe
      const pulse = Math.sin(baseTime * 3) * 0.15 + 0.85;
      wireframeMat.opacity = Math.min(1, (isHovered ? 0.95 : 0.75) * pulse);

      renderer.render(scene, camera);
    };

    animate();

    return () => {
      cancelAnimationFrame(animId);
      if (interactive) {
        container.removeEventListener('mousemove', onPointerMove);
        container.removeEventListener('mouseenter', onMouseEnter);
        container.removeEventListener('mouseleave', onMouseLeave);
        container.removeEventListener('click', onClick);
      }
      outerGeo.dispose();
      wireframeGeo.dispose();
      wireframeMat.dispose();
      innerGeo.dispose();
      innerMat.dispose();
      ringGeo.dispose();
      ringMat.dispose();
      particleGeo.dispose();
      particleMat.dispose();
      renderer.dispose();
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
    };
  }, [size, interactive]);

  return (
    <div
      ref={mountRef}
      className={`inline-flex items-center justify-center cursor-pointer select-none transition-transform hover:scale-110 active:scale-95 ${className}`}
      style={{ width: size, height: size }}
      title="Interactive 3D Cryptographic Core (Three.js) · Click to spin"
      aria-label="3D Cryptographic Core"
    />
  );
};
