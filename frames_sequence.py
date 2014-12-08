#!/usr/bin/env python
#-*- coding: utf-8 -*-
#-----------------------------------------------------------------------
# Author: delimitry
#-----------------------------------------------------------------------

def is_childless(node):
    """
    Check if node is childless
    """
    for n in nodes:
        parent, child = n[0], n[1]
        if node == parent:
            return False
    return True


def get_parents(node):
    """
    Get node's parent nodes
    """
    parents = []
    for n in nodes:
        parent, child = n[0], n[1]
        if node == child:
            parents.append(parent)
    return None if not parents else parents


def is_orphan(node):
    """
    Check if node is orphan
    """
    return get_parents(node) is None


def get_children(node):
    """
    Get all node's children
    """
    children = []
    for n in nodes:
        parent, child = n[0], n[1]
        if node == parent:
            if child not in children:
                children.append(child)
    return children


def build_frames_sequences(frame_nodes):
    """
    Build frames' sequences (from parent to child) using frame nodes list.
    The `frame_node` it is "(parent, child)" tuple.
    """
    all_sequences = []
    for n in nodes:
        parent, child = n[0], n[1]
        sequence = []
        if is_childless(child):
            sequence.append(child)
            parents = get_parents(child)
            if parents:
                sequence.append(parents[0])
                while True:
                    parents = get_parents(parents[0])
                    if not parents:
                        break
                    sequence.append(parents[0])
        if sequence:
            #print 'from parent to child', sequence[::-1]
            all_sequences.append(sequence[::-1])
    return all_sequences
